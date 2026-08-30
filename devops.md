# FireLint (FirewallGuard AI) — DevOps / Deployment Guide

Multi-tenant SaaS that analyzes SonicWall firewall Tech Support Reports (TSRs).
Customers upload TSRs (or the platform pulls them via the SonicOS REST API);
the analysis engine parses the configuration, evaluates ~67 built-in rules plus
DB-stored CEL rules, matches firmware against PSIRT/CVE intelligence,
correlates attack paths, scores the device (0–100 / A–F), and renders
PDF/CSV/JSON reports.

---

## 1. Technology stack

| Layer | Technology | Version / pin |
|---|---|---|
| Backend language | Python | 3.12 (image `python:3.12-slim`) |
| Web framework | FastAPI | 0.115.6 |
| App servers | gunicorn + uvicorn workers | gunicorn 23.0.0, uvicorn 0.34.0 |
| ORM / migrations | SQLAlchemy 2.0 + Alembic | 2.0.36 / 1.14.0 |
| DB driver | psycopg 3 (binary) | 3.2.3 |
| Background jobs | Celery (worker + beat) | 5.4.0 |
| Rule engine (custom rules) | cel-python (CEL expressions) | 0.1.5 |
| PDF/report rendering | ReportLab + svglib + Jinja2 + openpyxl | 4.2.5 / 1.3.0 / 3.1.4 / 3.1.5 |
| Auth | PyJWT (HS256), passlib+bcrypt, stdlib TOTP (RFC 6238) | bcrypt **pinned 4.0.1** (passlib compatibility — do not upgrade casually) |
| Secret encryption | cryptography (Fernet) for stored device credentials | 44.0.0 |
| Billing | Stripe SDK (degrades gracefully without API key) | 11.4.1 |
| Object storage | boto3 (S3) or local filesystem | 1.35.92 |
| Frontend | React 18 + TypeScript 5.7 + Vite 6 + Tailwind 3.4 + Recharts | see `frontend/package.json` |
| Frontend build/runtime | Node 20 (build stage) → static bundle on nginx 1.27-alpine | multi-stage `frontend/Dockerfile` |
| Database | PostgreSQL | 16 (dev compose; any supported 14+ should work, native ENUMs are used) |
| Cache / broker | Redis | 7 |
| Reverse proxy | nginx (serves SPA, proxies `/api/` to backend) | 1.27-alpine |

No server-side rendering; the frontend is a fully static SPA (hash routing)
that talks to the API under `/api/v1`.

---

## 2. Service topology

```
                    ┌────────────────────────────┐
  browser ── :8080 →│ web (nginx)                │
                    │  • static SPA (Vite build) │
                    │  • /api/ → proxy to api    │
                    └──────────────┬─────────────┘
                                   │
                    ┌──────────────▼─────────────┐      ┌──────────────┐
       :8000 ──────→│ api (gunicorn+uvicorn ×4)  │─────→│ postgres :5432│
                    │  FastAPI app  app.main:app │      └──────────────┘
                    └──────┬───────────┬─────────┘      ┌──────────────┐
                           │           └───────────────→│ redis :6379  │
                    enqueue│ (Celery, queue "analysis") │  db0 cache   │
                    ┌──────▼─────────────┐              │  db1 broker  │
                    │ worker (celery -c4)│──────────────│  db2 results │
                    │  TSR parse + rules │              └──────────────┘
                    │  + findings sync   │              ┌──────────────┐
                    └──────┬─────────────┘              │ storage vol/ │
                    ┌──────▼─────────────┐              │ S3 bucket    │
                    │ beat (celery beat) │              │ (TSR files,  │
                    │  60 s schedule tick│              │  reports)    │
                    └────────────────────┘              └──────────────┘
```

Six services (see `docker-compose.yml`):

| Service | Image / build | Command | Ports |
|---|---|---|---|
| `db` | `postgres:16` | — | 5432 (healthcheck: `pg_isready -U fgai`) |
| `redis` | `redis:7` | — | 6379 |
| `api` | `./backend` Dockerfile | `gunicorn app.main:app --worker-class uvicorn.workers.UvicornWorker --workers 4 --bind 0.0.0.0:8000 --timeout 120` | 8000 |
| `worker` | same backend image | `celery -A app.tasks.celery_app worker -Q analysis -c 4 --loglevel=info` | — |
| `beat` | same backend image | `celery -A app.tasks.celery_app beat --loglevel=info` | — |
| `web` | `./frontend` Dockerfile (Node 20 build → nginx) | nginx | 8080→80 |

All four backend roles (api, worker, beat) run the **same image**; only the
command differs. Redis DB usage: `db0` app cache / scan-concurrency locks,
`db1` Celery broker, `db2` Celery results.

---

## 3. Configuration (environment variables)

Settings are Pydantic `BaseSettings` (`backend/app/config.py`) with prefix
**`FGAI_`**; a `.env` file in the backend working directory is also honored.
Everything below is `FGAI_`-prefixed (e.g. `FGAI_DATABASE_URL`).

### Must set in production

| Variable | Purpose | Notes |
|---|---|---|
| `DATABASE_URL` | SQLAlchemy URL | `postgresql+psycopg://user:pass@host:5432/dbname` |
| `REDIS_URL` | cache / locks | `redis://host:6379/0` |
| `CELERY_BROKER_URL` / `CELERY_RESULT_BACKEND` | Celery | `redis://host:6379/1` and `/2` |
| `JWT_SECRET` | signs access/refresh tokens (HS256) | **secret, stable, rotatable only with forced re-login** |
| `CREDENTIAL_ENCRYPTION_KEY` | Fernet key for stored SonicOS device credentials | Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. If unset, derived from `JWT_SECRET` (dev convenience only — set explicitly in production, and never change it once devices have saved credentials). |
| `STORAGE_BACKEND` | `s3` or `local` | default `s3` |
| `S3_BUCKET` / `REGION_BUCKETS` | TSR + report object storage | boto3 credentials via standard AWS env/instance role |
| `LOCAL_STORAGE_DIR` | when `STORAGE_BACKEND=local` | must be a **shared persistent volume mounted on api AND worker** |
| `PUBLIC_APP_URL` / `PUBLIC_API_URL` | SSO redirects, Stripe return URLs | external HTTPS URLs |

### Optional / feature configuration

| Variable | Default | Purpose |
|---|---|---|
| `ENVIRONMENT` / `DEBUG` | `development` / `false` | environment label, debug flag |
| `ACCESS_TOKEN_TTL_MINUTES` / `REFRESH_TOKEN_TTL_DAYS` | 60 / 14 | token lifetimes |
| `LOCKOUT_THRESHOLD` / `LOCKOUT_MINUTES` | 5 / 15 | account lockout on failed logins |
| `RATE_LIMIT_ENABLED` / `RATE_LIMIT_PER_MINUTE` / `AUTH_RATE_LIMIT_PER_MINUTE` | true / 240 / 12 | per-IP fixed-window limiter (in-process middleware) |
| `MAX_TSR_SIZE_MB` | 64 | upload cap (nginx `client_max_body_size` is 80M) |
| `SCAN_MAX_RETRIES` / `SCAN_RETRY_BACKOFF_SECONDS` | 3 / 30 | scheduled-scan retry policy |
| `MAX_CONCURRENT_SCANS_PER_TENANT` | 3 | Redis-enforced concurrency cap |
| `SCHEDULE_TICK_SECONDS` | 60 | Celery Beat tick for due schedules |
| `SMTP_HOST` / `SMTP_PORT` / `ALERT_FROM_ADDRESS` | localhost / 587 / alerts@… | alert email |
| `SONICOS_VERIFY_TLS` | false | appliance certs are usually self-signed |
| `SONICOS_TIMEOUT_SECONDS` / `SONICOS_API_BASE` / `SONICOS_LOGIN_OVERRIDE` | 30 / `/api/sonicos` / true | SonicOS REST pull |
| `STRIPE_API_KEY` / `STRIPE_WEBHOOK_SECRET` / `STRIPE_PRICE_*` | empty | empty ⇒ billing runs in local/dev mode |
| `TRIAL_DAYS` | 14 | trial workflow |
| `PSIRT_PORTAL_URL` / `NVD_API_BASE` / `PSIRT_REFRESH_HOUR` | SonicWall/NVD / 4 (UTC) | daily advisory refresh (outbound HTTPS required) |
| `RETENTION_DAYS` / `RETENTION_PURGE_HOUR` | free 30 / pro 90 / msp 365; 5 UTC | per-plan data retention purge |
| `SECURITY_HEADERS_ENABLED` / `HSTS_MAX_AGE` / `CONTENT_SECURITY_POLICY` | true / 2y / see config | HSTS/CSP/X-Frame middleware |
| `REGIONS` / `DEFAULT_REGION` | us,eu,apac / us | data-residency bucket routing |

---

## 4. Build and deploy

### Quick start (single host, Docker Compose)

```bash
docker compose up --build            # web :8080, api :8000
# first run only — create schema + seed admin + system rules + default API flow:
docker compose exec api python -m app.bootstrap --seed \
    --email admin@example.com --password "StrongPass123!"
```

Access the product at **http://host:8080** (nginx serves the SPA and proxies
`/api/`). Port 8000 does not need to be public in production.

### Production notes

- Terminate TLS in front of the `web` nginx (or replace it with your ingress);
  the app emits HSTS/CSP headers itself when `SECURITY_HEADERS_ENABLED=true`.
- The API is stateless — scale `api` horizontally behind a load balancer.
  Rate limiting is per-process/per-IP; use a front-door limiter if you need a
  global budget.
- Scale `worker` replicas/concurrency for analysis throughput. A full analysis
  of a real 2–4 MB TSR (parse + ~67 rules + CEL rules + scoring + PDF-ready
  JSON) takes seconds; collection-style CEL rules add ~2–3 s per rule.
- Run **exactly one** `beat` instance.
- `gunicorn --timeout 120` and nginx `proxy_read_timeout 300s` accommodate
  large synchronous TSR uploads (up to 64 MB by app limit, 80 MB by nginx).
- Frontend dev server (`npm run dev`, :5173) is for development only; the
  production bundle is baked into the `web` image (`tsc -b && vite build`).

### Persistence (back these up)

| Data | Location |
|---|---|
| PostgreSQL | volume `pgdata` (all tenants, devices, analyses, findings, rules, audit log) |
| TSR files + rendered reports | volume `storage` (local backend) **or** S3 buckets |
| Redis | ephemeral (cache/broker); safe to lose, in-flight jobs will retry |

Note on growth: each completed analysis stores its full parsed snapshot
(including the complete TSR `config` tree, ≈1.5–3 MB JSON per real TSR) in
`analyses.result_json`. The per-plan retention purge bounds this; size your
Postgres storage accordingly.

---

## 5. Database schema and migrations

- Alembic is configured in `backend/alembic.ini`; `env.py` reads
  `Settings.database_url` (so `FGAI_DATABASE_URL` drives migrations too).
- **The migration tree has multiple heads.** Always run:
  `alembic upgrade heads` (plural), not `upgrade head`.
- App startup and `python -m app.bootstrap` run `Base.metadata.create_all()`:
  this **creates missing tables but never alters existing ones**. On an
  existing database, new columns/enum values still require Alembic (or the
  documented manual `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` statements in
  `CLAUDE.md`). Stale schema is the usual cause of HTTP 500 after upgrades.
- Schedule frequency `hourly` requires the native enum value:
  `ALTER TYPE schedulefrequency ADD VALUE IF NOT EXISTS 'hourly';`
- SQLite is supported for tests only; production targets PostgreSQL.

---

## 6. Background processing

- Queue: single Celery queue **`analysis`** (worker starts with `-Q analysis`).
- Jobs: TSR analysis runs, SonicOS API pulls, scheduled scans, PSIRT refresh
  (daily, `PSIRT_REFRESH_HOUR` UTC), retention purge (daily,
  `RETENTION_PURGE_HOUR` UTC).
- Celery Beat fires `run_due_schedules` every `SCHEDULE_TICK_SECONDS` (60 s);
  license-frequency cooldowns (monthly/weekly/daily/hourly) are enforced
  server-side, so duplicate ticks are harmless.
- `FGAI_INLINE_TASKS=1` executes analyses synchronously in the API process —
  used by the test suite; do not set it in production.

---

## 7. Security posture (operational)

- JWT (HS256) access/refresh tokens; MFA via stdlib TOTP with bcrypt-hashed
  backup codes; account lockout 5 fails / 15 min.
- RBAC roles (owner/admin/analyst/viewer) + `is_superadmin` platform-operator
  flag; tenant isolation is enforced from the JWT organization claim, never
  from request parameters.
- Device API credentials are Fernet-encrypted at rest
  (`CREDENTIAL_ENCRYPTION_KEY`).
- Security headers middleware (HSTS, CSP, X-Frame deny) — keep enabled behind
  TLS.
- OIDC SSO is JWKS-verified and is the production SSO path; SAML signature
  validation is intentionally not enforced (see `docs/SOC2.md`).
- Supply chain: `backend/requirements-dev.txt` provides `pip-audit` and
  `cyclonedx-bom`; a generated SBOM lives at `backend/sbom.json`. Known
  advisory exceptions are tracked in `docs/SOC2.md`.
- Uploaded TSRs contain real firewall configuration — treat the storage
  bucket/volume and database as sensitive. The repo's `TSRs/` directory is
  git-ignored on purpose.

---

## 8. Health checks and observability

- API: `GET /health` (no auth) — liveness/readiness for both `api` and, via
  image parity, a sanity check target after deploys. `GET /` returns app meta.
- Postgres: `pg_isready -U fgai` (already wired in compose).
- Worker/beat: standard Celery liveness (`celery -A app.tasks.celery_app
  inspect ping`) or process supervision.
- Logging: stdout/stderr (12-factor); notable loggers:
  `firewallguard.rule_engine` (CEL rule evaluation, fired global rules),
  `firewallguard.builder` (TSR uploads to the rule builder). Structured audit
  trail is persisted in the `audit_log` table (append-only).

---

## 9. Tests and CI

```bash
# Backend (SQLite + inline tasks are auto-configured by tests/conftest.py)
cd backend && pip install -r requirements.txt && python -m pytest tests/

# Frontend type-check + production build
cd frontend && npm install && npm run build
```

- Suite status at time of writing: 145 passed, 14 skipped.
- Skipped tests are gated on real reference TSRs; provide them via
  `FGAI_TEST_TSR`, `FGAI_GUI_TSR`, `FGAI_API_TSR`, or a directory of `.wri`
  files in `FGAI_TSR_DIR` (defaults to `<repo>/TSRs`, which is intentionally
  not committed).
- The suite refuses to run against a non-test database (it drops/creates all
  tables); it defaults to a throwaway SQLite file.

---

## 10. Known operational quirks

- `bcrypt` must stay pinned at 4.0.1 (passlib 1.7.4 compatibility).
- `alembic upgrade heads` — plural — because of parallel migration branches.
- `create_all()` on startup never alters existing tables (see §5).
- SonicOS API pulls default to `verify_tls=false` because appliances ship
  self-signed certificates; override per device or globally if you deploy a
  PKI.
- Stripe, SMTP, and PSIRT refresh all degrade gracefully when unconfigured or
  offline — the core analysis pipeline has no external runtime dependencies.
