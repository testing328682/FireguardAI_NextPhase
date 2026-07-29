Read FIREWALLGUARD-AI-SPEC.md and implement Phase 1 (MVP). The existing codebase has a working analysis engine, FastAPI scaffold, and React SPA. Build on top of it.

Phase 1 deliverables:

1. **Tenancy hardening**: Expand the User model with MFA fields (totp_secret, backup_codes, mfa_enabled). Add TOTP enrollment and verification endpoints. Add account lockout after 5 failed logins. Add rate limiting middleware (slowapi or custom).

2. **Alembic migrations**: Initialize Alembic in backend/. Create the initial migration from the existing SQLAlchemy models. Add the Finding model (with workflow states, assignee, due_date, justification, ticket_ref), FindingComment, AuditLog, and Schedule models. Generate migrations.

3. **Finding workflow**: Add API endpoints for finding state transitions (Open → Acknowledged → InProgress → Fixed, Open → FalsePositive, Open → AcceptedRisk, Open → Suppressed). Each transition requires a comment. Fixed findings auto-verify on next scan. AcceptedRisk requires admin sign-off and expiry date. Add FindingComment CRUD. Add bulk state-change endpoint.

4. **Scheduled scans**: Add the Schedule model and CRUD endpoints. Implement a Celery Beat schedule reader that produces scan tasks from the DB table. Enforce concurrency limits per tenant in Redis. Add exponential backoff retry (3 attempts) for failed scans.

5. **Dashboard API**: Add a GET /api/v1/dashboard endpoint returning: fleet posture (average score, grade distribution, 90-day trend), open findings funnel (Critical/High counts with yesterday delta), devices needing attention, recent audit events, compliance pass percentages.

6. **Audit log**: Add the AuditLog model and a utility function `log_action(db, user, action, resource_type, resource_id, before, after)`. Call it from auth, user management, finding state changes, device changes, and schedule changes. Add GET /api/v1/audit-log with pagination and filters.

7. **Frontend dashboard**: Build the /dashboard route with panels for fleet posture (score gauge + sparkline), findings funnel, devices needing attention, recent activity, and quick actions. Build the /findings route with cross-device table, severity/category/status filters, saved views, and bulk actions. Build /findings/:id with the finding detail, state-change buttons, comment thread, and history timeline. Build /settings/profile with MFA enrollment.

8. **Email notifications**: On new Critical finding or scan failure, send email to subscribed users via the existing alerting module. Add user notification preferences to the settings page.

Start by reading the existing code to understand what's already built, then extend it. Run tests after each major change. Commit after each deliverable.
