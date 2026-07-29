# FirewallGuard AI — Build Specification

> **Implementation status (addendum).** All four phases are implemented, plus
> post-phase work delivered since. Highlights beyond the original spec, with
> details in `CLAUDE.md`:
> - **Dual-format TSRs** — GUI- and SonicOS-API-collected reports both supported.
>   API TSRs (whitespace-collapsed) are auto-detected and normalised to
>   GUI-equivalent text (`firewallguard/tsr/normalize.py`), giving identical
>   parsed data, findings, severity counts and score (verified parity).
> - **Connect via API** — onboard a firewall without a manual upload: authenticate,
>   pull the TSR, analyse it (`app/sonicos.py`, `POST /devices/connect`), with
>   per-step status messages.
> - **API TSR Parser Config** (server admin) — the entire SonicOS API workflow is
>   editable from the UI (steps, endpoints, methods, headers, query, body, auth,
>   SSL, success conditions, value extraction), with Gen7/Gen8 versioning, one
>   Active config used automatically, and a step-by-step connection tester
>   (`app/api_flow.py`, model `ApiFlowConfig`, `/platform/api-configs*`).
> - **Superadmin tooling** — Platform overview, TSR Analysis Tester, and the API
>   config page; Rules page has a GUI/API support view.

## Project overview

Build **FirewallGuard AI**, a multi-tenant SaaS platform that continuously analyzes the security posture of SonicWall firewalls. Customers connect their firewalls (manually or via API), the platform parses the Tech Support Reports, evaluates them against a catalog of detection rules, correlates findings into attack paths, matches firmware against the SonicWall PSIRT vulnerability database, scores the configuration, and presents findings through a web dashboard with a triage workflow.

The platform must support multiple organizations (tenants), multiple users per organization with role-based access, scheduled automatic scans, an admin-configurable rule engine, and a finding workflow for triage (Fixed, False Positive, Accepted Risk, Suppressed).

## Technology stack

- **Backend**: Python 3.12, FastAPI, SQLAlchemy 2.0, Alembic for migrations, Pydantic v2, Celery for background processing, Redis as broker and cache, PostgreSQL 16 as primary database.
- **Frontend**: React 18 + TypeScript, Vite, Tailwind CSS, deployed as a static SPA behind nginx.
- **Storage**: S3-compatible object storage for raw TSR files and generated PDF reports.
- **Reporting**: ReportLab for PDF generation, Jinja2 for HTML report templates.
- **Auth**: JWT access and refresh tokens, bcrypt password hashing, TOTP MFA, SAML 2.0 and OIDC for enterprise SSO.
- **Deployment**: Docker, Docker Compose for development, Kubernetes manifests for production.
- **Observability**: Structured JSON logs, Prometheus metrics, OpenTelemetry tracing.
- **CI/CD**: GitHub Actions building and pushing container images, automated migrations.

## Domain model

Implement these core entities with appropriate foreign keys and tenant scoping:

- `Organization` (the tenant): name, plan tier (Free, Professional, MSP), billing details, is_msp flag, data residency region.
- `User`: belongs to an Organization, has a role (Owner, Admin, Analyst, Auditor, MSPOperator), MFA enrollment status, password hash, last login.
- `Customer`: a managed client. For direct customers, one Customer per Organization. For MSPs, many Customers per Organization.
- `Device`: belongs to a Customer. Fields: serial number, model, firmware, friendly name, location tag, environment tag, business unit tag, connection method (manual or api), connection credentials reference (encrypted), schedule configuration, latest score, latest grade.
- `DeviceCredential`: encrypted credentials for API-pull devices, stored in a vault, never returned by the API as plaintext.
- `Schedule`: per-device scan schedule. Fields: frequency (daily, weekly, monthly, manual), time of day, timezone, day of week or month, enabled flag, blackout windows.
- `Tsr`: a single uploaded or pulled TSR. Fields: device, storage key (S3 path), filename, size, uploaded by, source (manual or api).
- `Analysis`: the result of running the pipeline on a TSR. Fields: device, tsr, status (queued, running, complete, failed), score, grade, finding count, severity breakdown, result JSON, generated at.
- `Finding`: a single detection from one analysis. Fields: analysis, device, rule (with version), severity, title, category, description, evidence, business impact, technical impact, remediation, verification steps, compliance mappings, affected object (name, type, detail), exploitability, status (Open, Acknowledged, InProgress, Fixed, FalsePositive, AcceptedRisk, Suppressed), assignee, due date, ticket reference, justification, accepted risk expiry, parent rule version.
- `FindingComment`: comments on findings with author, timestamp, body, type (status_change, comment, attachment).
- `Rule`: a detection rule. Fields: rule ID, title, category, severity, description, condition (CEL expression), remediation text, compliance mappings, applicable firmware ranges, owner (system or tenant_id), enabled flag, current version.
- `RuleVersion`: every edit creates a new version row. Fields: rule, version number, condition, edited by, edited at, change note.
- `RuleSuppression`: per-tenant suppressions or severity overrides. Fields: rule, tenant, device (optional, null means tenant-wide), action (disable, override_severity), value, reason, expires at.
- `DriftEvent`: comparison between two analyses on the same device. Fields: device, previous analysis, current analysis, alert count, severity counts, alerts JSON.
- `Advisory`: PSIRT advisory record. Fields: advisory ID, CVE list, CVSS, severity, generations, affected version range, fixed version, summary, reference URL, published date, last refreshed.
- `AlertSubscription`: notification preferences. Fields: organization, channel (email, slack, webhook, teams), target, triggers (new_critical, service_disabled, firmware_vuln, critical_drift, scan_failed).
- `AuditLog`: append-only record of privileged actions. Fields: organization, user, action, resource type, resource ID, before JSON, after JSON, IP address, user agent, timestamp.
- `Integration`: external system connections. Fields: organization, type (jira, servicenow, slack, splunk, sentinel), configuration (encrypted), enabled flag.
- `ApiToken`: programmatic API tokens. Fields: organization, name, scopes, hashed token, last used, expires at.

## Tenancy and authorization

All queries that read or write tenant data must filter on `organization_id` derived from the authenticated user's JWT. No endpoint accepts `organization_id` as a parameter from the client.

Implement these roles with a hierarchical permission model where higher roles inherit lower-role permissions:

- **Owner**: full control including billing and organization deletion.
- **Admin**: manage users, integrations, rules, schedules, and all data within the organization.
- **Analyst**: upload TSRs, run scans, triage findings, change finding states.
- **Auditor**: read-only access plus export and download permissions.
- **MSPOperator**: cross-customer access within an MSP organization, with the same effective rights as Analyst on each managed customer.

Implement these authentication features:

- Email and password sign-up with email verification.
- Bcrypt password hashing with the bcrypt library pinned to a passlib-compatible version.
- TOTP-based MFA, with backup codes.
- JWT access tokens (60-minute TTL) and refresh tokens (14-day TTL) with refresh token rotation.
- SAML 2.0 and OIDC SSO with Okta, Microsoft Entra ID, and Google Workspace, with role mapping from IdP groups.
- API token authentication for programmatic access, with scopes and revocation.
- Rate limiting per IP and per user.
- Account lockout after repeated failed attempts.

## Backend services

Implement the backend as a single FastAPI application plus separate worker and scheduler processes. The analysis pipeline (already built) parses a TSR, evaluates rules, matches firmware against the advisory database, correlates findings into attack paths, computes the score, and persists results. Extend it so:

- Rule evaluation reads from the database-stored rule catalog (with CEL conditions), not from hard-coded Python rules.
- Tenant rule suppressions and severity overrides are applied after evaluation.
- Finding records are linked to the specific rule version that produced them.

## Feature 1 — Dashboard

The dashboard is the post-login landing page. Panels: fleet posture card (average grade, device grade distribution, 90-day sparkline), open findings funnel (Critical/High counts with delta vs yesterday), devices needing attention (failed/overdue/downgraded), recent audit activity, compliance roll-up (CIS/NIST/PCI/ISO/SonicWall BP pass percentages), and quick-action buttons.

## Feature 2 — Adding firewalls

Two paths: manual TSR upload (wizard: name/tags → file drop → auto-detect serial → upsert device → analyze) and API pull (wizard: hostname/port → credentials → connection test → save encrypted credential → schedule). For SonicWall MSW/CSC tenants, support platform-level credential that enumerates all managed devices. Failed credentials surface warnings in dashboard and fire alerts.

## Feature 3 — Scheduled scans

Per-device Schedule record: frequency (daily/weekly/monthly/manual/cron), time-of-day, timezone, day-of-week/month, blackout windows, enabled toggle. Celery Beat reads the schedule table. Concurrency limits per tenant enforced in Redis. Failed scans retry with exponential backoff (3 attempts) then alert. Optional drift-triggered scans via SonicOS config checksum polling.

## Feature 4 — Rule engine admin GUI

Rules stored in DB as CEL expressions evaluated against the parsed snapshot. GUI: library view (searchable table), rule editor (metadata + visual condition builder producing CEL + live test panel against real snapshots), approval workflow (Draft → Submitted → Approved by Admin → Active), tenant overrides (disable, severity change, remediation override with reason and expiry), versioning with diff view, full audit logging.

## Feature 5 — Reports dashboard

Device detail page (identity, latest grade, trend, scan timeline, drift events). Analysis report view (score gauge, attack paths, PSIRT advisories, findings table with affected-object column, expandable details, download buttons). Findings explorer (cross-device, filterable by severity/category/status/assignee/device/age, saved views, bulk actions). Comparison view (two scans, drift diff). Compliance dashboard (framework-by-framework heat map). Scheduled email digests.

## Feature 6 — Finding workflow

States: Open → Acknowledged → InProgress → Fixed (auto-verified on next scan; reopens if still detected), FalsePositive (suppresses instance, requires justification), AcceptedRisk (requires justification + Admin sign-off + expiry date; auto-reopens on expiry), Suppressed (Admin only, rule-level). Per-finding actions: assign, comment, attach, set due date, link ticket. History timeline on every finding. Bulk actions from findings explorer.

## Integrations

Slack, Microsoft Teams, Email (SMTP), Jira (OAuth/PAT, bidirectional sync), ServiceNow (REST, bidirectional sync), Splunk HEC, Microsoft Sentinel, generic webhook (HMAC-SHA256 signed), PagerDuty. Each has test action, enabled toggle, delivery log.

## PSIRT auto-refresh

Daily job: scrape SonicWall PSIRT portal + cross-reference NVD, normalize version ranges, content-hash change detection, changelog for Admins, manual refresh button.

## Billing

Free (1 device, 1 upload, no schedule), Professional (unlimited, all features, 90-day retention), MSP (multi-customer, fleet overview, white-label, 12-month retention). Stripe Billing integration. 14-day trial.

## Audit log

Append-only log of: auth events, user management, rule changes, finding state changes, device changes, schedule changes, integration config, data exports. Queryable in UI, exportable as CSV/JSON.

## Frontend routes

/login, /sso, /mfa, /dashboard, /devices, /devices/:id, /devices/new, /analyses/:id, /findings, /findings/:id, /rules, /rules/:id, /customers, /compliance, /integrations, /settings/organization, /settings/users, /settings/profile, /settings/api-tokens, /audit-log.

## Design system

Dark theme default. Security-console aesthetic: deep slate base (#0a0e16), JetBrains Mono for codes/serials/CVEs, Space Grotesk/Inter for UI text. Severity: Critical #ff4d4d, High #ff8a3d, Medium #f5c451, Low #4a9eff, Info #7a879b. Grade: A #39d98a, B #9ad94a, C #f5c451, D #ff8a3d, F #ff4d4d. Score gauge: 270-degree arc. Hairline borders, 4px border-radius panels, dense data tables, subtle grid texture background.

## Phasing plan

- **Phase 1 (MVP)**: tenancy hardening, MFA, dashboard, manual upload, scheduled scans, finding workflow with all states, PDF/CSV reports, email notifications.
- **Phase 2**: SonicOS API-pull, rule admin GUI with CEL, compliance dashboard, Slack integration, public REST API, drift comparison UI.
- **Phase 3**: SAML/OIDC SSO, MSP multi-tenancy, Jira/ServiceNow, Stripe billing, PSIRT auto-refresh.
- **Phase 4**: SOC 2 prep, multi-region, white-label, mobile enhancements, advanced analytics.

## Acceptance criteria

For each feature: automated tests (happy path, auth, validation, tenant isolation), works on latest Chrome/Firefox/Safari/Edge, Alembic migrations (up and down), rule tests with sample snapshots, docs updated, audit log captures new actions, notifications fire when expected, security review passed.
