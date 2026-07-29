Read FIREWALLGUARD-AI-SPEC.md and implement Phase 2. Phase 1 must be complete before starting.

Phase 2 deliverables:

1. **SonicOS API pull**: Add DeviceCredential model (encrypted with Fernet, key from env). Add a connection wizard endpoint: POST /api/v1/devices/connect that accepts hostname, port, username, password, tests against SonicOS /api/sonicos/version, and saves the credential. Add a worker task that pulls TSR via /api/sonicos/export/tech-support-report, stores in S3, queues analysis. Surface connectivity failures in the dashboard.

2. **Rule engine with CEL**: Install cel-python. Add Rule and RuleVersion models. Migrate existing catalog.py rules into seed data (each rule's condition as a CEL expression, metadata as DB fields). Build a CEL evaluator service that compiles and runs expressions against a snapshot dict. Modify the analysis pipeline to read rules from DB instead of the Python registry. Apply tenant RuleSuppression overrides after evaluation.

3. **Rule admin GUI**: Build /rules (library table: ID, title, category, severity, source, state, filterable/searchable). Build /rules/:id with tabs: Overview (metadata form), Condition (CEL editor with syntax highlighting + visual tree builder), Test (select a snapshot, evaluate, show fire/no-fire + evidence), History (version list with diff), Overrides (tenant overrides with reason/expiry). Implement approval workflow: Draft → Submitted → Approved by Admin.

4. **Compliance dashboard**: Build /compliance with one tab per framework (CIS v8, NIST CSF 2.0, PCI DSS 4.0, ISO 27001, SonicWall BP). Each tab shows a matrix: devices as columns, controls as rows, colored pass/fail. Click a cell to see contributing findings.

5. **Slack integration**: Add Integration model. Build /integrations page with Slack card: webhook URL input, test button, event toggles (new_critical, scan_failed, weekly_digest). Worker sends Slack messages on configured events.

6. **Public REST API docs**: Ensure all endpoints have OpenAPI descriptions. Add Swagger UI at /docs and ReDoc at /redoc. Add API token model, CRUD endpoints at /settings/api-tokens, and token-based auth as an alternative to JWT.

7. **Drift comparison UI**: Build a comparison view accessible from device detail page: select two analyses, display the drift diff (new findings, resolved, changed configs) grouped by category with severity indicators.

Run tests after each deliverable. Commit after each.
