Read FIREWALLGUARD-AI-SPEC.md and implement Phase 4. Phases 1-3 must be complete.

Phase 4 deliverables:

1. **SOC 2 preparation**: Add data retention policies configurable per plan tier. Implement GDPR data export (all user data as JSON). Implement right-to-erasure endpoint with documented retention exceptions. Add a security headers middleware (HSTS, CSP, X-Frame-Options). Add dependency scanning with pip-audit. Generate SBOM with cyclonedx-bom. Document the change log, access review, and incident response procedures.

2. **Multi-region data residency**: Add a region field to Organization. Configure the storage layer to route TSRs and reports to region-specific S3 buckets. Document the deployment topology for multi-region (separate DB per region or row-level security). Implement region selection in the sign-up flow.

3. **White-label MSP reports**: Add organization-level branding configuration (logo URL, company name, primary color, contact info). Pass branding into the ReportLab PDF generator so MSPs can deliver reports under their own brand. Add a branding preview in /settings/organization.

4. **Mobile-friendly enhancements**: Audit all frontend routes for responsive design. Ensure the dashboard, findings explorer, and finding detail work on 375px-width viewports. Add touch-friendly controls for the findings table filters and finding state transitions.

5. **Advanced analytics**: Add a trends page showing score progression per device over 12 months, mean-time-to-remediate per severity, finding recurrence rate, top 10 most common rules firing across the fleet, and category breakdown evolution. Use Recharts or Chart.js for visualizations.

Run tests after each deliverable. Commit after each.
