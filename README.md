# FirewallGuard AI

Continuous security posture analysis for SonicWall firewalls. Upload a Tech
Support Report (TSR) and FirewallGuard AI returns a scored, prioritised set of
findings, correlated multi-stage attack paths, firmware vulnerability
intelligence, configuration-drift tracking across uploads, and
executive/technical reports.

This repository contains the backend platform: a reusable analysis engine
(`firewallguard`) and the multi-tenant API and worker stack (`app`).

## What it does

- **Parses** a SonicWall TSR into a structured, JSON-serialisable snapshot.
- **Accepts both TSR formats** — collected from the firewall GUI *or* via the
  SonicOS API. API TSRs (whitespace-collapsed) are auto-detected and normalised
  to GUI-equivalent text, so both formats yield identical parsed data, findings,
  severity counts and score (verified parity on the reference device).
- **Onboards firewalls two ways** — manual TSR upload, or **Connect via API**
  (authenticate, pull the TSR, and analyse it with no manual upload).
- **Evaluates** the snapshot against an evidence-gated rule catalog spanning
  management exposure, authentication, security services, VPN cryptography, SSL
  VPN, access control, NAT, object hygiene, certificates, licensing, high
  availability and logging.
- **Correlates** individual findings into named attack paths with a
  kill-chain narrative.
- **Scores** the configuration from 0 to 100 with an A–F grade.
- **Tracks drift** by comparing a new snapshot against the previous one and
  emitting prioritised change alerts.
- **Reports** through executive and technical PDFs plus CSV and JSON exports.
- **Alerts** by email or webhook when critical conditions appear.

## Architecture

The platform separates a pure analysis library from the service layer.

- `firewallguard/tsr` — TSR reader and parser. The reader splits the report
  into nested sections; the parser turns each section into structured data with
  independent, defensive functions per domain. `tsr/normalize.py` detects an
  API-collected (whitespace-collapsed) TSR and reconstructs GUI-equivalent text
  (record headers, key/value segmentation, value fix-ups) so one parser serves
  both formats.
- `firewallguard/rules` — the rule engine and the detection catalog. Rules are
  evidence-gated: a rule only fires when the TSR explicitly shows the condition,
  and any rule exception degrades to an informational note rather than failing
  the scan.
- `firewallguard/intelligence` — firmware/PSIRT matching and deterministic
  attack-path correlation.
- `firewallguard/analytics` — risk scoring and configuration-drift detection.
- `firewallguard/report` — PDF, CSV and JSON report generation.
- `firewallguard/pipeline.py` — orchestrates parse → rules → firmware →
  correlation → scoring into a single analysis dictionary.
- `app/` — FastAPI application, SQLAlchemy models, Celery worker, storage,
  alerting and JWT/RBAC security. `app/sonicos.py` is the SonicOS REST client;
  `app/api_flow.py` is a DB-driven flow engine that lets a server admin edit the
  whole API workflow (endpoints, methods, headers, auth, success checks, value
  extraction) from the UI without code changes.
- `frontend/` — React + TypeScript single-page web app (Vite, Tailwind) for
  uploading TSRs and viewing/downloading reports.

The full analysis result is a plain dictionary, so it can be stored,
transmitted and re-loaded without any database dependency. Tenant isolation is
enforced in the service layer: every query filters on the authenticated user's
`organization_id`, which is taken from the JWT and never from a request
parameter.

### Request flow

A device is onboarded either by uploading a TSR or by connecting over the
SonicOS API:

1. **Upload** — an analyst uploads a TSR to a customer; or **Connect via API** —
   the platform authenticates to the firewall, downloads the TSR, and continues
   automatically (the active, server-admin-configured API flow drives the calls).
2. The API normalises the TSR (GUI or API format), persists the raw report to
   object storage, upserts the device (keyed on serial) and queues an analysis.
3. A Celery worker runs the pipeline, stores the result, computes drift against
   the previous analysis and dispatches any matching alerts.
4. Clients fetch findings, attack paths, drift history, the fleet overview, and
   download reports.

## Technology

Python, FastAPI, SQLAlchemy 2.0, PostgreSQL, Redis, Celery, ReportLab.
Containerised with Docker and orchestrated locally with Docker Compose; the
production target is Kubernetes on AWS with S3-backed storage.

## Running locally

### Full stack (web + API + worker + Postgres + Redis)

```bash
docker compose up --build
# Web app:  http://localhost:8080
# API docs: http://localhost:8000/docs
```

The web app (`frontend/`) is a React single-page interface: sign in, onboard a
firewall (upload a TSR or Connect via API), and view or download reports. It
includes a sample-data mode so the UI can be explored without a running backend.
Server-admin (superadmin) accounts get extra left-nav pages: **Platform**,
**TSR Tester**, and **API TSR Parser Config**.

### Analysis engine only (no services required)

```bash
cd backend
python -m firewallguard.cli analyze /path/to/TSR.wri --out ./reports
python -m firewallguard.cli drift OLD_TSR.wri NEW_TSR.wri
```

### Tests

```bash
cd backend
pip install -r requirements.txt
pytest
```

## API surface (v1)

- `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `GET /api/v1/auth/me`,
  `POST /api/v1/auth/users`
- `GET/POST /api/v1/customers`
- `GET /api/v1/devices`, `GET /api/v1/devices/{id}`
- `POST /api/v1/customers/{id}/tsrs` (upload + analyse)
- `POST /api/v1/devices/connect` (Connect via API: authenticate, pull TSR,
  analyse — pre-registered `device_id` or new `customer_id`),
  `POST /api/v1/devices/{id}/pull` (re-pull)
- `GET /api/v1/devices/{id}/analyses`, `GET /api/v1/analyses/{id}`
- `GET /api/v1/analyses/{id}/report/executive|technical`,
  `GET /api/v1/analyses/{id}/export/csv|json|xlsx`
- `GET /api/v1/devices/{id}/drift`
- `GET /api/v1/fleet`
- `GET/POST/DELETE /api/v1/alerts/subscriptions`
- Server admin (superadmin): `POST /api/v1/platform/analyze-tsr` (ad-hoc TSR
  tester), `GET/POST/PUT/DELETE /api/v1/platform/api-configs`,
  `POST /api/v1/platform/api-configs/{id}/activate`,
  `POST /api/v1/platform/api-configs/test`

## SonicOS API integration & dual-format TSRs

- **Dual-format TSRs.** GUI- and API-collected reports are both supported. An
  API TSR is auto-detected and normalised to GUI-equivalent text, so the parser,
  rule catalog and scoring run unchanged and produce identical results. The
  Rules page has a **GUI TSR / API TSR** view, and superadmins get a **TSR
  Analysis Tester** page (upload a report, auto-detect the format, see findings).
- **Configurable API flow.** The **API TSR Parser Config** page (superadmin)
  makes the entire SonicOS API workflow editable from the UI — ordered steps,
  endpoints, HTTP methods, headers, query params, body, auth type, SSL
  verification, success conditions and value extraction — with versioning
  (e.g. Gen7/Gen8), a single **Active** configuration used automatically by
  customers, and a step-by-step **connection tester** (URL, method, headers,
  status, body, timing, success/failure). If SonicWall changes an endpoint or
  format, it can be updated from the portal without code changes. The default
  SonicOS Gen7 flow is seeded automatically.

## Roles

`owner` > `admin` > `msp_operator` > `analyst` > `viewer`. A higher role
satisfies any lower requirement. Uploading requires at least `analyst`; user and
subscription management requires `admin`.

## Monetisation tiers

- **Free** — a single device and one TSR upload, full analysis and on-screen
  findings. Intended for evaluation.
- **Professional** — unlimited uploads for a single organisation, drift
  history, scheduled re-analysis, PDF/CSV/JSON exports and email/webhook alerts.
- **MSP** — multi-customer tenancy, the fleet overview across all managed
  devices, per-customer segregation, MSP operator roles and white-label
  reporting.

## Firmware intelligence data

The bundled PSIRT dataset (`firewallguard/intelligence/data/psirt.json`) is
curated from the official SonicWall PSIRT portal
(`https://psirt.global.sonicwall.com/vuln-list`) and NVD, and carries real
advisory identifiers, CVEs, CVSS scores and fixed-firmware versions. Version
matching is SonicOS- and generation-aware (build-number accurate). SonicWall
publishes new advisories regularly, so the dataset records a `last_refreshed`
date and should be refreshed on a schedule in production. See
`COVERAGE_COMPARISON.md` for the advisories matched on the reference device.

## Security and privacy notes

A TSR can contain sensitive material (for example SNMP community strings and
internal addressing). Raw reports are stored per-tenant in object storage with
lifecycle policies, and analyses retain a structured snapshot rather than the
raw text. Deployments should enable encryption at rest and restrict storage
access to the worker role.
