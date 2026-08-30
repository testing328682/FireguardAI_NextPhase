# FirewallGuard AI

Multi-tenant SaaS for SonicWall firewall security posture analysis. Upload or pull TSRs, evaluate against a rule catalog, correlate attack paths, match firmware PSIRT/CVEs, score and report.

## Full specification

Read `FIREWALLGUARD-AI-SPEC.md` for the complete build specification, domain model, feature details, and phasing plan. Reference it before building any new feature.

## Build commands

```bash
# Backend (Python 3.12)
cd backend && pip install -r requirements.txt
python -m firewallguard.cli analyze /path/to/TSR.wri --out ./reports
python -m pytest tests/

# Frontend (Node 18+)
cd frontend && npm install && npm run dev    # dev server on :5173
cd frontend && npm run build                 # production build

# Full stack (Docker)
docker compose up --build                    # web :8080, api :8000
docker compose exec api python -m app.bootstrap --seed --email admin@example.com --password "StrongPass123!"
```

## Architecture

```
backend/
  firewallguard/          # Analysis engine (standalone, no DB needed)
    tsr/reader.py         # Splits TSR into sections
    tsr/parser.py         # Parses sections into structured snapshot dict
    tsr/parser_ext.py     # Extended parsers (flood/DDoS, local users, WLAN, CFS, CPU, auth)
    tsr/normalize.py      # Dual-format support: detect GUI vs API TSR + normalize API→GUI text
    tsr/generic.py        # Generic full-config capture → snapshot["config"] (complete TSR tree)
    tsr/sonicos_keys.txt  # Harvested GUI-TSR key dictionary (drives API key re-segmentation)
    tsr/sonicos_sections.txt  # Harvested section-name catalog (drives marker restoration)
    rules/engine.py       # Finding dataclass, Rule, RuleRegistry with CEL support
    rules/catalog.py      # Core detection rules (~25)
    rules/catalog_parity.py  # Parity rules: per-object ACR/AOB/SVC/NAT/IPSEC/FW/AUTH/PERF (~32)
    rules/catalog_info.py # Informational inventory checks (~10)
    intelligence/firmware.py  # PSIRT advisory matching, version comparison
    intelligence/data/psirt.json  # Real advisory data from SonicWall PSIRT portal
    intelligence/correlation.py   # Attack path correlation
    analytics/scoring.py  # 0-100 score, A-F grade
    analytics/drift.py    # Configuration drift detection
    report/generator.py   # PDF (ReportLab), CSV, JSON exports
    pipeline.py           # Orchestrator: parse → rules → firmware → correlate → score
    cli.py                # Standalone CLI
  app/                    # FastAPI service layer
    main.py               # App entrypoint, rate-limit middleware, includes routers
    models.py             # SQLAlchemy ORM (multi-tenant); Device.configured, Device.hidden_severities, Device.analyze_mode, Org.hidden_severities
    schemas.py            # Pydantic response models; DeviceOut, DeviceRegisterRequest, DeviceDetailOut, TsrHistoryItem
    security.py           # JWT, bcrypt, RBAC, MFA token, lockout, API-token auth
    mfa.py                # TOTP (stdlib RFC 6238) + bcrypt-hashed backup codes
    crypto.py             # Fernet encryption for stored secrets (Phase 2)
    sonicos.py            # SonicOS REST client for API-pull devices (Phase 2)
    rule_engine.py        # CEL evaluator, _SYSTEM_RULE_CEL defaults, evaluate_system_rule_filters(), evaluate_authored_system_rules() (generative global rules), check_firmware_compliance(), seed_system_rules(), rule_api_support()/api_unsupported_system_keys() (API-TSR support)
    sso.py                # OIDC (JWKS-verified) + SAML SSO; role mapping (Phase 3)
    ticketing.py          # Jira/ServiceNow create + bidirectional status sync (Phase 3)
    billing.py            # Stripe + plan-limit enforcement + trial workflow + org visibility endpoint (Phase 3)
    psirt_refresh.py      # PSIRT advisory refresh with content-hash detection (Phase 3)
    privacy.py            # GDPR export + right-to-erasure with exceptions (Phase 4)
    retention.py          # Per-plan data-retention purge (Phase 4)
    secheaders.py         # Security headers middleware: HSTS/CSP/X-Frame (Phase 4)
    ratelimit.py          # Per-IP fixed-window rate-limit middleware
    audit.py              # Append-only audit log + log_action utility
    findings_sync.py      # Persist pipeline findings; auto-reopen/resolve lifecycle
    scheduler.py          # Schedule next-run arithmetic + Redis scan concurrency
    database.py           # Session management
    config.py             # Pydantic settings from env vars
    storage.py            # S3/local storage abstraction
    tasks.py              # Celery workers; scans, API pull, PSIRT refresh, Beat; firmware compliance check runs before storing counts
    alerting.py           # Email/webhook/Slack alerts; per-user notifications
    bootstrap.py          # DB schema creation + seed + system-rule seed (dev)
    routers/              # auth, devices, analyses, reports, fleet, alerts,
                          #   findings, schedules, dashboard, audit_log,
                          #   rules, compliance, integrations, tokens,
                          #   sso, billing, psirt, privacy, analytics,
                          #   platform, platform_config (generations, devices, firmware)
  alembic/                # Migrations (env.py reads Settings.database_url)
    versions/
      76dd31d38a63        # initial schema
      5df0c07f2d68        # phase 2 schema
      ae94d241e5a6        # phase 3 schema
      56360aa7cdc7        # phase 4 schema
      9cf3ff84eee9        # user is_superadmin
      f2747a4266fc        # user phone address
      a1b2c3d4e5f6        # device configured flag
      b2c3d4e5f6a7        # missing device columns (last_analysis_at, severity counts)
      c3d4e5f6a7b8        # hidden_severities columns (org + device)
  alembic.ini
  requirements-dev.txt    # pip-audit + cyclonedx-bom (security tooling)
  sbom.json               # generated CycloneDX SBOM
  tests/                  # test_engine, test_api, test_ratelimit, test_phase2,
                          #   test_phase3, test_phase4, conftest
docs/                     # SOC2.md, DEPLOYMENT-MULTIREGION.md
frontend/                 # React 18 + TypeScript + Vite + Tailwind
  src/App.tsx             # Auth state, hash routing (nav), demo mode; collapsible sidebar;
                          #   routes /devices/:id → DeviceDetailView
  src/components/
    Devices.tsx           # Device list; modal registration (name+serial+confirm);
                          #   Configure modal (TSR/api); row click → detail;
                          #   Configured/Not Configured badges; fixed action menu
    DeviceDetail.tsx      # Device info card; TSR history table with delete;
                          #   upload new TSR; Go to Findings button
    FindingsExplorer.tsx  # Device-centric: device-list default → device-specific view;
                          #   TSR selection dropdown (snapshot-based findings);
                          #   comparison modal (summary + detailed side-by-side);
                          #   visibility settings (global + per-device toggles);
                          #   category column + filter; clickable KPI cards
    UploadPanel.tsx       # TSR upload accepting pre-registered device_id
    Rules.tsx             # Rule library; modal-based creation with category dropdown;
                          #   16 predefined categories + Custom
    Dashboard.tsx         # Fleet KPI cards, trend chart, compliance bars
    FindingsTable.tsx     # Reusable findings table component
    FindingDetail.tsx     # Single finding detail view with triage
    ScoreGauge.tsx        # 270-degree score gauge
    Login.tsx             # Login with MFA support
    Modal.tsx             # Enterprise confirm/prompt dialogs
    icons.tsx             # SVG icon components
    Platform.tsx          # Cross-tenant operator dashboard
    ProductConfig.tsx     # Device generations, model mappings, firmware
    CelBuilder.tsx        # Visual CEL rule builder; lazy searchable explorer
                          #   over the complete TSR snapshot (snapshot.config)
    Profile.tsx           # User profile settings
    Organization.tsx      # Org settings, billing, branding, SSO
    Compliance.tsx        # Per-framework compliance matrices
    Integrations.tsx      # Slack, Teams, Jira, ServiceNow, webhooks
    ApiTokens.tsx         # Programmatic API token management
    Customers.tsx         # MSP customer management
    Trends.tsx            # Recharts analytics dashboard
    AdvancedDashboard.tsx # New dashboard (Phase 1: toolbar + shell; widgets pending)
  src/lib/                # api.ts (client), types.ts, router.ts (hash router), ui.ts, theme.ts
```

## Device onboarding (two-step flow)

Devices are registered first, then configured:

1. **Register**: `POST /devices` with `{customer_id, friendly_name, serial}`.
   Creates a Device with `configured=False`. Each device consumes one license
   (`billing.enforce_device_limit`). Duplicate serials rejected (409).

2. **Configure via TSR**: `POST /customers/{id}/tsrs?device_id=...` — parses TSR,
   validates serial matches the registered device, marks `configured=True`,
   updates model/firmware, queues analysis. Serial mismatch → 400.

3. **Configure via API**: `POST /devices/connect` with `{device_id, hostname, port,
   username, password}` — probes SonicOS API, validates serial matches, stores
   encrypted credentials, marks `configured=True`, queues pull. Serial mismatch
   returns `connection_status=failed`.

Device model has `configured: bool` (default False). The devices list shows
"Configured" (green) or "Not Configured" (yellow) badges. Unconfigured devices
show "—" for posture/findings and have a "Configure…" action in the menu.

## Device detail page

`GET /devices/{device_id}/detail` returns `DeviceDetailOut` with:
- All DeviceOut fields + `tsr_count` + `tsrs: [TsrHistoryItem]`
- Each `TsrHistoryItem` has: id, filename, size_bytes, uploaded_at, analysis_id, analysis_status, analysis_score, analysis_grade

`DELETE /tsrs/{tsr_id}` cascade-deletes findings → analysis → TSR.
`GET /tsrs/{tsr_id}/download` — downloads the original TSR file (tenant-scoped).

The DeviceDetail page shows:
- Device info card with a **Retrieve Mode** selector (Manual/Upload or API)
- Header buttons adapt to retrieve mode: "Upload New TSR" (manual) or "Pull Now" (API)
- **API Configuration** section (API devices): saved credentials, edit form with Test & Connect, password masking with Show/Hide toggle
- **Analyze Mode** toggle (Manual/Auto) with per-license-frequency schedule config
- **TSR history table** with download (↓) and delete (×) buttons per row

## Findings (device-centric, snapshot-based)

The findings page is now device-centric:

**Default view**: Shows a device list with per-device metrics (score, severity counts,
total open, last scan). Clicking a device opens the device-specific view.
"Configure Filter" button opens global visibility settings modal.

**Device-specific view**: Shows the selected device with:
- TSR selection dropdown (lists all completed analyses, defaults to latest)
- Export buttons (Technical PDF + CSV)
- Compare Findings button (when ≥2 completed analyses exist)
- Configure Filter button (device visibility settings)
- Clickable KPI cards (click severity/status to filter findings)
- Category column + filter in findings table
- Full findings table with bulk actions

**Snapshot-based findings**: Selecting an older TSR loads findings from that
analysis's `result_json` snapshot via `GET /analyses/{analysis_id}/findings`,
cross-referenced with the live findings table for current triage status.
This preserves the exact set of findings from that TSR, unlike the live
findings table where rows are mutated across scans.

**Severity counts**: Only count findings with active statuses (open, acknowledged,
in_progress). Resolved/fixed findings don't inflate the severity KPI cards.

**Clickable KPIs**: On the main page, clicking a severity/status KPI opens a
Quick Findings modal showing matching findings across all devices with device
references. On the device view, clicking KPIs sets the corresponding filter.

## TSR comparison

`GET /devices/{device_id}/compare?previous=X&current=Y` returns `DriftCompareResponse`
with new_findings, resolved_findings, config_changes, severity_counts.

The comparison modal offers:
- **Summary view**: count cards (New, Resolved, Config Changes, Score Δ) +
  detailed lists of added/resolved findings with severity badges +
  side-by-side table (Severity | Finding | Older TSR | Newer TSR)
- **Detailed Report**: loads all findings from both TSRs via
  `listAnalysisFindings`, displays full side-by-side table with severity,
  title, category, and per-TSR triage status. Includes Print/PDF button.

## Findings visibility settings

- **Organization model**: `hidden_severities: JSON` (list of severity strings, e.g. `["Low","Info"]`)
- **Device model**: `hidden_severities: JSON` (per-device override)

Endpoints:
- `PATCH /organization/visibility` — global hidden severities
- `PATCH /devices/{device_id}/visibility` — device-specific hidden severities

UI:
- **Global**: Main findings page → Configure Filter modal → per-severity On/Off toggle switches
- **Device**: Device findings view → Configure Filter modal → per-severity toggles +
  "Inherit from Global" checkbox. When checked, toggles are disabled and device
  uses global settings. When unchecked, device has its own settings.

Device settings override global. Filtering happens client-side on `visibleRows`.

## New API endpoints (post-Phase 4)

| Method | Path | Description |
|--------|------|-------------|
| POST | /devices | Register device (name + serial, configured=false) |
| GET | /devices/{id}/detail | Device info + TSR history with analysis results |
| DELETE | /tsrs/{id} | Delete TSR + cascade analysis + findings |
| GET | /tsrs/{id}/download | Download original TSR file |
| GET | /analyses/{id}/findings | Snapshot-based findings from result_json |
| PATCH | /devices/{id}/visibility | Device-level hidden severities |
| PATCH | /organization/visibility | Org-level hidden severities |
| GET | /devices/{id}/credentials | Get saved API credentials (password never returned) |
| PUT | /devices/{id}/credentials | Test + update API credentials (saves only on success) |
| PATCH | /devices/{id} | Update friendly_name, connection_method, analyze_mode |
| GET | /devices/{id}/schedule | Get device scan schedule |
| PUT | /devices/{id}/schedule | Create/update scan schedule (hourly/daily/weekly/monthly) |

## Dual-format TSR support (GUI vs API)

SonicWall TSRs come in two shapes that carry the same configuration:

- **GUI TSR** (collected from the firewall web UI): section markers on their own
  lines, `Key : Value` records, space-separated lists and column-aligned tables.
  This is the format the parser, ~67 system rules, and the Rule Builder were built
  against. **Unchanged** — it remains authoritative.
- **API TSR** (collected via the SonicOS API): whitespace-collapsed — all
  whitespace stripped and one space inserted after every colon. Markers run inline,
  `Key:Value` records merge, times become `08: 27: 50`, and space-separated lists
  collapse (`X0 X1` → `X0X1`).

**Approach: normalize + reuse rules (one code path).** `tsr/normalize.py`
reconstructs GUI-equivalent text from an API TSR so the existing reader / parser /
rule engine apply identically — there is no separate "API rule set", and the
**full** rule set runs on API TSRs.

- `detect_tsr_format(text)` → `"gui"` | `"api"` (compares own-line vs inline
  `#…_START` markers; needs ≥10 markers, API if ≤25% are on their own lines).
- `normalize_api_tsr(text)`:
  - rejoins comma-wrapped values (`"a,\nb"` → `"a, b"`);
  - restores `#…_START/END` markers to their own lines (names re-spaced from
    `sonicos_sections.txt`);
  - `_reconstruct_blocks` rebuilds per-object record structure the export
    collapsed onto one line: `--X Table--` markers, `-----Name-----` /
    `----General----` dash headers, VPN `--- SA N ---` headers, the
    space-packed access-rule header (`Rule N src -> dst Action Service … (State)`),
    address type markers (`HOST:`/`NETWORK:`…), member `Handle:` boundaries, and
    the `Logging/Management`+`Iface` runs;
  - `_segment_kv` re-segments run-on `Key:Value` records by longest-suffix match
    against the `sonicos_keys.txt` dictionary;
  - `_fixups` re-spaces model/firmware and VPN proposal tokens (`DHGroup2` →
    `DH Group 2`, `AggressiveMode` → `Aggressive Mode`).
- `normalize_tsr(text)` → `(normalized_text, format)`; GUI passes through verbatim.

The object-detail parsers (`parse_address_objects`, `parse_services`,
`parse_access_rules`, `parse_firewall_settings`, `parse_administration`) use
`\s*`-tolerant colon/phrase regexes so they read both the spaced GUI form and the
normalized API form. These changes are zero-width for GUI input.

**Parity.** On the reference pair (same firewall, GUI vs API TSR) the analyses are
**identical**: same score and grade (36.4 / F), same finding count (123), same
per-severity counts, and no rule fires a different number of times. The parsed
intermediate data also matches exactly (address objects 169 / groups 144 /
empty-groups 66, services 231 / groups 52, access rules 146). Reaching exact
parity required, beyond the block reconstruction above:
- `_MEMBER_RE` — rebuild `member: Name:<n> Handle:<h>` as one colon-space-free
  line so segmentation does not explode it (else every group read as empty);
- a larger dash-header length cap (names are doubled in parens, e.g.
  `-----Foo(Foo)-----`), with `=`/`:` excluded so a stats footer
  (`----#FQDN_AOs=3,...----`) is not taken as a record header;
- bracketed IPv6/MAC literal collapse (`[\n fe80: : 2eb8: ...\n]` →
  `[fe80::2eb8:...]`) so IPv6 objects keep distinct values;
- space-tolerant `N times referenced by Module:` so referenced objects are not
  miscounted as unused.

- `rule_engine.rule_api_support(key, condition)` → `"full"` | `"none"`. With the
  current normalizer every section reconstructs, so `_API_LOSSY_SECTIONS` and
  `_API_FORCE_NONE` are **empty** and this returns `"full"` for all rules. The
  mechanism is retained to flag any future irrecoverable rule.
- `rule_engine.api_unsupported_system_keys(db)` consequently returns `[]` — no
  rule is suppressed on API TSRs. `tasks.run_analysis_inline` and the tester
  endpoint still apply it (currently a no-op).

**Surfaces.** `RuleOut.api_support` is exposed by `/rules`; the Rules page has a
**GUI TSR / API TSR** toggle that adds an API-compatibility badge (all rules show
Supported). Superadmins get a **TSR Tester** page (`#/tsr-tester`) backed by
`POST /api/v1/platform/analyze-tsr` (upload + auto/gui/api, runs the pipeline
without persisting). Tests: `backend/tests/test_api_tsr.py`, including a
file-gated GUI/API parity test (`FGAI_GUI_TSR` / `FGAI_API_TSR`).

## Complete TSR snapshot (CEL Rule Builder)

`parse_tsr` attaches a structure-preserving sweep of the **entire** TSR as
`snapshot["config"]` (`tsr/generic.py`, `build_config_tree`). The curated keys
(`system`, `administration`, …) are unchanged; `config` is additive, so every
existing CEL path keeps working. Engine version bumped to 0.10.0.

- **No hardcoded section list.** The tree is driven by the `#…_START/_END`
  markers in the uploaded TSR; sections nest exactly as their markers nest.
  Unknown sections/fields are retained, never discarded.
- **Node shape** (keys omitted when empty): `fields` (typed `Key : Value`
  pairs; repeated lone keys become lists), `items` (records detected from
  repeated-key blocks, e.g. per-interface listings), `blocks` (named
  dash-header blocks: `--Table--` groups and `-----Name-----` records),
  `lines` (unparsed raw lines, capped at 200/node with `lines_total` marking
  truncation — dumps are truncated *explicitly*, config is not), `sections`
  (nested sections). Values are conservatively typed: exact
  enabled/disabled/yes/no/on/off/true/false → bool, plain integers → int,
  everything else string; symmetric quotes are unwrapped.
- **Marker healing.** Real SonicOS TSRs contain mismatched markers (observed:
  `FIRWARE` for `FIRMWARE`, `PKTIO NIC` vs `PKTIO_NIC`, `AWS API_END` closing
  `AWS API Details`, `Firewall : Security Policy Table_END` closing
  `Firewall : Access Rules`). An END that matches no open section exactly or
  after normalization (casefold, strip non-alphanumerics) closes the innermost
  open section; an END with nothing open is a stray and is ignored. Without
  this one unterminated section swallows the rest of the document.
- **CEL paths** follow the existing convention (`snapshot` root, celpy): dot
  access for identifier keys, index syntax otherwise, e.g.
  `snapshot.config["System : Time"].sections["Blade_1_TIME"].fields["Use NTP"] == true`.
  Because `config` is in the pipeline snapshot, rules built on these paths
  fire during real scans and are stored in `Analysis.result_json` (~1.5–2.7 MB
  JSON per real TSR; tree build ~0.2 s, celpy conversion ~0.1 s).
- **Builder endpoints** (`routers/rules.py`): upload now runs `normalize_tsr`
  first (API-format TSRs parse identically); the upload response includes
  `tsr_format`. `POST /rules/builder/test` falls back to the caller's saved
  `BuilderSnapshot` when neither `snapshot` nor `analysis_id` is supplied, so
  the UI never re-sends multi-MB snapshots. **Route-order fix:** the builder
  test route must be declared before `POST /rules/{rule_id}/test` — the
  dynamic route was capturing `rule_id="builder"` (404 "Rule not found"),
  which had silently broken the builder's Run Test button.
- **Frontend** (`CelBuilder.tsx`): `SnapshotExplorer` — lazy tree (children
  render only when expanded; 150-per-page "Show more" chunks), debounced
  key/value search with click-to-reveal, CEL-correct path generation
  (`JSON.stringify` for bracket keys), and click-to-prefill operator/value
  from the actual TSR value. Container rows have a ⊕ button for exists/size
  conditions. The Save card offers the same rule metadata as the Rules page
  creation form — Severity, Category, Remediation (`SEVERITIES` and
  `RULE_CATEGORIES` are shared from `lib/ui.ts`).
- **Tests**: `tests/test_generic_config.py` — synthetic-TSR structure/typing/
  marker-healing/CEL tests plus endpoint tests; reference-TSR tests are gated
  on `FGAI_TSR_DIR` (default `<repo>/TSRs`) and assert every marker-delimited
  section appears in the tree.
- **Authored global rules are generative.** The rules table holds three kinds
  of rows: catalog mirrors (source=system, key in the Python catalog —
  findings come from catalog code; stored CEL is only an optional filter,
  currently feature-flagged off in `make_pipeline_hooks`), tenant custom
  rules (source=custom — CEL generates findings via `evaluate_custom_rules`),
  and **authored global rules** (source=system, org NULL, key *outside* the
  catalog — i.e. saved from the CEL Rule Builder). The latter are evaluated by
  `rule_engine.evaluate_authored_system_rules()` inside
  `make_pipeline_hooks.extra_findings_fn`, so they generate findings for
  every tenant's analyses (all paths: manual TSR upload, API pull, scheduled
  scans) and flow through suppressions and scoring like any other finding.
  Before this, a builder-saved system rule was visible in every rule library
  but never executed — visible rule, no findings.
  Tests: `tests/test_global_rules.py` (unit + end-to-end via TSR upload +
  file-gated acceptance test on the reference TSR).

## Configurable API flow (API TSR Parser Config)

The SonicOS API workflow is fully editable from the Server Admin portal — no code
changes when SonicWall changes an endpoint/auth/format.

- **Model** `ApiFlowConfig` (`app/models.py`, platform-global): `name`,
  `version_label` (Gen7/Gen8…), `is_active` (exactly one), `auth_type`,
  `verify_tls`, `timeout_seconds`, `api_base`, and `steps` (ordered JSON).
- **Engine** `app/api_flow.py` — `run_flow(config, ctx)` executes the steps with
  stdlib urllib + a shared cookie jar. Each step: `method`, `path`, `auth`
  (basic/bearer/none/inherit), `headers`, `query`, `body`, `success`
  (`status_codes` / `json_not_false` / `body_contains`), `extract`
  (json/regex/header → named vars), `is_tsr` (this step's body is the TSR),
  `continue_on_error`. Templates `{{ip}} {{port}} {{username}} {{password}}
  {{basic_credentials}}` + extracted vars. Returns per-step traces (auth header
  redacted), `extracted`, and `tsr_text`. `get_active_config` (no side effects) /
  `ensure_default_config` (seeds the default Gen7 flow) / `config_to_dict`.
- **Endpoints** (superadmin, `routers/platform.py`): `GET/POST /api-configs`,
  `GET/PUT/DELETE /api-configs/{id}`, `POST /api-configs/{id}/activate`,
  `POST /api-configs/test` (runs a saved or inline config against a firewall,
  returns step traces; persists nothing).
- **Integration**: `devices._run_api_flow` and `tasks.pull_and_analyze` use the
  active config when present, else fall back to the hardcoded `SonicOSClient`
  (so tests with no config exercise the legacy path). The captured TSR runs
  through the unchanged normalizer + engine via `tasks.ingest_tsr_bytes`.
- **Schema bootstrap**: `app/main.py` startup runs `create_all()` (creates the
  new table on a plain image rebuild — never alters existing tables); `bootstrap`
  seeds the default config. The new table needs no `down -v`.
- **Frontend**: superadmin page `ApiFlowConfig.tsx` (`#/api-config`) — version
  list with Active toggle, structured step editor, and an embedded connection
  tester showing per-step URL/method/headers/status/body/time/success.

## Connect via API (SonicOS REST)

A firewall can be onboarded without a manual TSR upload. `app/sonicos.py`
(`SonicOSClient`) implements the SonicWall KB flow:

- `login()` — `POST {base}/api/sonicos/auth` with HTTP Basic auth,
  `Accept`/`Content-Type: application/json`, and JSON body `{"override": true}`
  (Gen7; `settings.sonicos_login_override`). Success = HTTP 2xx without an
  explicit `success:false`.
- `export_tech_support()` — `GET {base}/export/tech-support-report`, returns raw
  TSR bytes; `logout()` releases the session (best effort).
- TLS verification is off by default (self-signed appliance certs);
  `verify_tls` is configurable per request and globally
  (`settings.sonicos_verify_tls`).
- Errors are raised as `SonicOSError` with a `kind` (`invalid_credentials`,
  `auth_failed`, `ssl_error`, `timeout`, `unreachable`, `api_disabled`,
  `http_error`, `bad_response`) and `status_code`, so the UI can explain failures.

`POST /api/v1/devices/connect` (`app/routers/devices.py`) authenticates,
downloads the TSR, identifies serial/model/firmware (TSR first, `/version`
fallback), then **reuses `tasks.ingest_tsr_bytes`** to store and analyse the TSR
exactly like an uploaded one (same normalizer + engine → identical findings). It
supports two modes and returns per-step status (`steps`) plus `error_kind` /
`http_status`:
- `device_id` — connect a pre-registered device (TSR serial must match);
- `customer_id` — register-and-connect a new firewall in one step.

Credentials are Fernet-encrypted in `DeviceCredential`; scheduled/on-demand
re-pulls go through `tasks.pull_and_analyze` (also via `ingest_tsr_bytes`).
Frontend: the **Connect via API** tab on a device (`ConnectInline` in
`Devices.tsx`) has TLS-verify and **Save password** checkboxes and renders the
step list. Manual TSR upload is unchanged. Mock `SonicOSClient` in tests
(`tests/test_api_connect.py`).

## Automated API scanning & scheduling

Devices with `connection_method="api"` support two analyze modes
(`Device.analyze_mode`, default `"manual"`):

- **Manual** — user clicks "Pull Now". The license frequency is enforced at the
  API level: a pull is only allowed after the cooldown window has elapsed since
  the last analysis (monthly=30d, weekly=7d, daily=24h, hourly=1h). Rate-limited
  attempts return a clear "Next analysis available in Xh Ym" message.
- **Auto** — the user configures a recurring `Schedule` via the Device Detail
  page (day-of-month for monthly, day-of-week for weekly, hour+minute for daily,
  minute-only for hourly). A Celery Beat process (`docker-compose.yml` `beat`
  service) fires `run_due_schedules` every 60s, dispatches API pulls for due
  schedules, and respects the same license cooldown (skipping runs with a log
  message when still in the window).

When `analyze_mode` is changed via `PATCH /devices/{id}`, the schedule is
automatically enabled (auto) or disabled (manual). Switching modes does not
require a separate schedule save.

Schedule frequencies include `hourly` (added to `ScheduleFrequency` enum;
requires `ALTER TYPE schedulefrequency ADD VALUE 'hourly'` in PostgreSQL since
the column uses a native ENUM).

## Devices page enhancements

**Bulk selection & deletion**: Checkbox column (select-all header + per-row),
row number (#) column, bulk action bar with selected count and "Delete Selected"
button (with confirmation dialog). Selection is filtered-view aware.

**Filters**: Multi-select dropdowns for Status (Configured/Not Configured),
License (Active/Expired), Firmware (dynamic from loaded devices), and Posture
(A–F grades). All filters combine together. Active filters appear as blue pill
chips with individual × remove buttons. A Reset button clears all filters.

**Device menu positioning**: The three-dot (⋯) context menu opens to the left of
the button, flips above when viewport space is insufficient, and recalculates on
scroll/resize. Render-hidden-then-position approach guarantees correct placement
on first click.

## Conventions

- Prefer Python 3.12 features. Type hints on all function signatures.
- FastAPI endpoints: tenant isolation via `organization_id` from JWT, never from request params.
- Rules are evidence-gated: only fire when the TSR explicitly shows the condition. Never infer from missing data.
- Per-object findings: one Finding per affected object (access rule, address object, VPN policy). Each Finding carries `object_name`, `object_type`, `object_detail`.
- Findings carry `compliance` as `Dict[str, List[str]]` mapping framework names to control IDs.
- The snapshot is a plain JSON-serializable dict. No ORM objects in the analysis pipeline.
- Frontend: dark-theme security console. Severity colors: Critical #ff4d4d, High #ff8a3d, Medium #f5c451, Low #4a9eff, Info #7a879b.
- Pin `bcrypt==4.0.1` in requirements.txt (passlib compatibility).
- DELETE endpoints returning 204 must use `return Response(status_code=204)` pattern, not the decorator `status_code` param (FastAPI compatibility).
- Use `Modal.confirm()` / `Modal.prompt()` instead of `window.confirm()` / `window.prompt()` for enterprise-grade dialogs.
- Modal overlays use `fixed inset-0 z-30 bg-black/50` backdrop + `z-40 grid place-items-center` container + `onClick={e.stopPropagation()}` on inner div.
- Severity counts for KPI cards: only count findings with active statuses (open, acknowledged, in_progress), not resolved/fixed.
- Device registration is separate from configuration; serial validation is mandatory on both TSR upload and API connect.
- Schedule frequencies include `hourly` (requires PostgreSQL `ALTER TYPE schedulefrequency ADD VALUE 'hourly'` — the column uses a native ENUM).

## License system

Two SQLAlchemy bugs caused the license system to fail silently and with 500 errors:

1. **Malformed count query** (`plans.py` and `devices.py`): `sqlfunc.count(Device.id).where(...)` is
   invalid — SQLAlchemy's `count()` returns a `Function`, not a `Select`, so `.where()` raises
   `AttributeError` at runtime. Fix: `db.scalar(select(sqlfunc.count(Device.id)).where(...))`.
   This crash prevented `get_license_bundles` from returning free-license info (Issue 1) and caused
   500 on Professional/MSP registration (Issue 2).

2. **Timezone-naive comparison**: SQLite stores datetimes without timezone info. Comparing a naive
   `datetime` to `datetime.now(tz.utc)` raises `TypeError`. Fix: `if expires.tzinfo is None:
   expires = expires.replace(tzinfo=tz.utc)` before any comparison in both `plans.py` and
   `devices.py`.

3. **Free license not created**: `ensure_free_license(db, org)` creates a `LicensePurchase` (1
   device, 30 days, monthly) at registration. It was never called because the crash above aborted
   the plan-check path. This is now called in `auth.py` at registration (defensive; won't block
   signup if it fails).

## Testing Plans (validity_minutes)

The `validity_minutes` field appeared to not persist — every save posted `0`. Root cause was
entirely in the **frontend**; the backend was correct throughout.

The React controlled `<select value={validityMins}>` was initialized to `0`, but no `<option>` has
`value={0}`. React renders the first option visually but fires no `onChange` event, so the state
never moved from `0`. Every `POST /plans` body contained `validity_minutes: 0`.

Fix in `frontend/src/components/PlanManager.tsx`:
- When the Testing checkbox is ticked, seed `validityMins` to `5` if it is currently falsy:
  ```tsx
  onChange={(e) => { setTesting(e.target.checked); if (e.target.checked && !validityMins) setValidityMins(5); }}
  ```
- Render the select with `value={validityMins || 5}` so it always matches an option.

`create_plan` in `plans.py` was also cleaned of all diagnostic `print`/`logger.debug` calls,
redundant `setattr` loops, and the raw-SQL `UPDATE` fallback that had been added as workarounds.
The endpoint is now its minimal correct form.

## Local environment & operational notes (this machine)

State as of 1 July 2026:

- **Project status.** All four phases (1–4) are implemented plus post-Phase-4
  enhancements including: device onboarding (registration + configuration with
  serial validation), device detail page with TSR history, device-centric
  findings with snapshot-based TSR selection, TSR comparison with detailed
  side-by-side view, findings visibility settings (global + per-device),
  category column + filter, clickable KPI cards, modal-based creation flows.
  Most recent work (see the dedicated sections above): **dual-format TSR support**
  (GUI ↔ API parity), **Connect via API**, **API TSR Parser Config**
  (configurable API flow), **license system fixes** (two malformed SQLAlchemy
  queries + timezone-aware comparison), and **Testing Plans validity_minutes fix**
  (React controlled-select mismatch), **automated API scanning & scheduling**
  (Manual/Auto analyze mode with hourly/daily/weekly/monthly schedules + Celery
  Beat + license-frequency cooldown enforcement), **device bulk selection &
  deletion**, **device multi-filter bar** (Status/License/Firmware/Posture),
  **API credentials management** (view/edit/test/save with Fernet encryption,
  Save Password toggle, password masking), **TSR download** from history,
  **TSR Retrieve Mode** switching, **device context menu positioning fix**.
  Backend suite: 83 passed / 14 skipped / 1 known pre-existing failure.
  The TSR-dependent engine tests are skipped unless `FGAI_TEST_TSR` /
  `FGAI_GUI_TSR` / `FGAI_API_TSR` point at reference reports. Frontend builds
  clean.
- **Not a git repository.** Nothing has been committed. Initialize git when ready.
- **Runtime topology.** Runs via Docker Compose: `db` (Postgres), `redis`, `api`
  (:8000), `web` (:8080, nginx prod bundle), `worker`, `beat` (Celery Beat for
  scheduled scans). **Prefer :8080** for access.
- **Docker on Windows.** `docker` is not on PATH; binary at
  `C:\Program Files\Docker\Docker\resources\bin\docker.exe`.
- **Database.** Docker Postgres creds are `fgai/fgai/fgai`, reachable inside
  containers as host `db`. Host `:5432` is shadowed by a native Postgres.
- **Schema changes.** `bootstrap`'s `create_all` does not alter existing tables.
  Apply Alembic migrations (`alembic upgrade heads`) or run manual ALTER TABLE
  commands. Stale volume is the usual cause of 500 errors.
- **Platform operator account.** `tm328682@gmail.com` is role `owner` with
  `is_superadmin = true`. Password: `TCPip@00`.
- **Account lockout.** 5 failed logins lock for 15 minutes.
- **Migrations have multiple heads.** Use `alembic upgrade heads` (not `head`).
  Branches: `a1b2c3d4e5f6` (configured flag) and `9cf3ff84eee9` (is_superadmin).
  Newest: `d6e7f8a9b0c1` (analyze_mode, on the `c3d4e5f6a7b8` branch).
- **Missing columns / ENUM values workaround:** If migrations fail, run:
  ```sql
  ALTER TABLE devices ADD COLUMN IF NOT EXISTS last_analysis_at TIMESTAMPTZ;
  ALTER TABLE devices ADD COLUMN IF NOT EXISTS critical_count INT DEFAULT 0;
  ALTER TABLE devices ADD COLUMN IF NOT EXISTS high_count INT DEFAULT 0;
  ALTER TABLE devices ADD COLUMN IF NOT EXISTS medium_count INT DEFAULT 0;
  ALTER TABLE devices ADD COLUMN IF NOT EXISTS low_count INT DEFAULT 0;
  ALTER TABLE organizations ADD COLUMN IF NOT EXISTS hidden_severities JSONB DEFAULT '[]'::jsonb;
  ALTER TABLE devices ADD COLUMN IF NOT EXISTS hidden_severities JSONB DEFAULT '[]'::jsonb;
  ALTER TABLE devices ADD COLUMN IF NOT EXISTS analyze_mode VARCHAR(16) DEFAULT 'manual' NOT NULL;
  ALTER TYPE schedulefrequency ADD VALUE IF NOT EXISTS 'hourly';
  ```
- **Findings counts.** Devices page fetches live counts from findings table.
  Findings page only counts active-status findings (open/acknowledged/in_progress).
- **CEL condition tips.** String values with spaces need quotes.
  Use `&&` for AND, `||` for OR. Use `.contains()` for substring matching.
- **Known security tooling note.** `pip-audit` flags advisories on pinned deps
  (pyjwt, cryptography, jinja2, starlette, pytest); tracked in `docs/SOC2.md`.
  SAML signature validation is intentionally not enforced — OIDC is the production
  SSO path.
- **Manual Findings (Jul–Aug 2026).** Users can now create, edit, and delete
  manual findings on the Device Findings page. Manual findings (`source="manual"`)
  have `analysis_id=NULL`, persist across re-analyses, and participate in all
  dashboards, scores, reports, and analytics identically to parser findings.
  Backend: `POST /devices/{id}/findings`, `PUT/DELETE /findings/{id}`.
  Migration `m1n2o3p4q5r6_manual_findings.py` adds `source` column and makes
  `analysis_id` nullable.
- **Advanced Dashboard Phase 1 (Aug 2026).** New page at `/#/advanced-dashboard`
  with reusable toolbar components (CustomerFilter, TimeRangeFilter, LastUpdated,
  RefreshButton, CustomizeButton). Widgets pending for Phase 2.
