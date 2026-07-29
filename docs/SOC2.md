# FirewallGuard AI — SOC 2 Readiness

This document describes the controls, procedures and evidence that support a SOC 2
Type II examination. It complements the in-product controls (audit log, RBAC, MFA,
encryption, retention) described in `CLAUDE.md`.

## Data protection

- **Encryption in transit.** All traffic is served over TLS; HSTS is enforced by
  the `SecurityHeadersMiddleware` (`Strict-Transport-Security`, plus CSP,
  `X-Frame-Options: DENY`, `X-Content-Type-Options`, `Referrer-Policy`,
  `Permissions-Policy`).
- **Encryption at rest.** Stored secrets (device passwords, integration tokens,
  OIDC client secrets) are Fernet-encrypted (`app/crypto.py`). Object storage and
  the database rely on provider-managed encryption at rest.
- **Secret management.** `FGAI_CREDENTIAL_ENCRYPTION_KEY`, `FGAI_JWT_SECRET` and
  Stripe keys are supplied via environment/secret manager and never committed.

## Access control

- Role hierarchy: Owner > Admin > MSPOperator > Analyst > Viewer, enforced by
  `require_role`. Tenant isolation is derived from the JWT `organization_id`,
  never from client input.
- MFA (TOTP + backup codes) is available to all users; account lockout after 5
  failed logins; per-IP rate limiting on auth endpoints.
- Programmatic access uses scoped, revocable API tokens (bcrypt-hashed).

## Data retention

- Retention windows per plan tier are defined in `settings.retention_days`
  (Free 30d, Professional 90d, MSP 365d) and may be overridden per organization
  (`data_retention_days`). A daily Celery job (`purge_expired_data`) deletes
  analyses, findings and TSR blobs past the window.

## GDPR / privacy

- **Right of access / portability (Art. 15/20):** `GET /api/v1/privacy/me/export`
  (self) and `GET /api/v1/privacy/users/{id}/export` (admin) return all personal
  data as JSON.
- **Right to erasure (Art. 17):** `POST /api/v1/privacy/users/{id}/erase`
  anonymises PII. Retention exceptions (audit log, finding history) are anonymised
  rather than deleted and are returned in the response for transparency.

## Change-management procedure

1. All changes land via pull request with at least one reviewer.
2. Database changes ship as Alembic migrations, verified `upgrade`/`downgrade`.
3. CI runs the test suite, `pip-audit` (dependency CVEs) and SBOM generation.
4. Releases are tagged; the deployment pipeline runs migrations before rollout.

## Access-review procedure (quarterly)

1. Export the user list per organization and confirm role assignments with owners.
2. Review API tokens; revoke unused or stale tokens (`last_used_at`).
3. Review SSO group→role mappings against the IdP's current groups.
4. Record the review outcome in the audit log (action `access.review`).

## Incident-response procedure

1. **Detect** — alerting (email/Slack), error monitoring, anomalous audit events.
2. **Triage** — classify severity; assign an incident owner.
3. **Contain** — revoke affected tokens/credentials, disable compromised accounts,
   rotate `FGAI_*` secrets if exposure is suspected.
4. **Eradicate & recover** — patch, redeploy, restore from backup if needed.
5. **Notify** — affected customers within the contractual/regulatory window.
6. **Post-mortem** — root-cause analysis and corrective actions within 5 business
   days; tracked to closure.

## Dependency scanning & SBOM

```bash
cd backend
pip install -r requirements-dev.txt
pip-audit -r requirements.txt          # fail the build on known CVEs
cyclonedx-py requirements requirements.txt -o sbom.json   # CycloneDX SBOM
```
CI runs both on every build; `sbom.json` is published as a release artifact.

### Known advisories (current build)

The `pip-audit` control is active and currently flags advisories against pinned
dependencies that should be remediated in a coordinated dependency bump:

- `pyjwt 2.10.1` → 2.13.0
- `cryptography 44.0.0` → 46.0.6
- `jinja2 3.1.4` → 3.1.6
- `starlette 0.41.3` → ≥0.47 (must be bumped together with FastAPI, which pins it)
- `pytest 8.3.4` (dev only) → 9.x

These are tracked under the change-management process; `starlette` in particular
requires upgrading FastAPI in lockstep, so it is scheduled rather than applied
piecemeal. The point of the control is that the scan surfaces them on every build.
