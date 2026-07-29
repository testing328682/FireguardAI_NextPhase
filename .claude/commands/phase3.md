Read FIREWALLGUARD-AI-SPEC.md and implement Phase 3. Phases 1-2 must be complete.

Phase 3 deliverables:

1. **SAML/OIDC SSO**: Integrate python-saml3 for SAML 2.0 and authlib for OIDC. Add SSO configuration model per organization. Build /sso route and callback handler. Map IdP groups to application roles. Support Okta, Microsoft Entra ID, and Google Workspace. Add /settings/organization SSO configuration UI.

2. **MSP multi-tenancy**: Extend the fleet endpoint to aggregate across all Customers in an MSP Organization. Build /customers page (list, add, edit managed clients). Add MSPOperator role that can switch customer context. Build a fleet-level dashboard showing all managed devices ranked by risk. Add per-customer segregation in the findings explorer.

3. **Jira integration**: Add Jira configuration in /integrations (OAuth app or PAT, project, issue type, field mapping). When a finding is Acknowledged, optionally create a Jira issue. Sync state changes bidirectionally via Jira webhook receiver endpoint. Display linked ticket status on finding detail.

4. **ServiceNow integration**: Same pattern as Jira but using ServiceNow REST API. Configure table, field mapping. Bidirectional state sync.

5. **Stripe billing**: Integrate stripe-python. Add plan management to /settings/organization. Implement metered billing for devices and scans beyond plan limits. 14-day trial workflow that downgrades to Free on expiry. Enforce plan limits (device count, scheduled scans, integrations) at the API layer.

6. **PSIRT auto-refresh**: Build a daily Celery task that fetches advisories from https://psirt.global.sonicwall.com and cross-references NVD. Content-hash change detection. Changelog visible to Admins under /settings. Manual refresh button. On relevant changes, flag affected devices for re-evaluation on next scan.

Run tests after each deliverable. Commit after each.
