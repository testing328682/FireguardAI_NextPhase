# Multi-Region Data Residency — Deployment Topology

FirewallGuard AI supports per-organization data residency. Each organization has a
`region` (`us`, `eu`, `apac`; see `settings.regions`). TSRs and rendered reports
are stored in region-specific S3 buckets, and the storage key is prefixed with the
region (`<region>/orgs/<org>/devices/<device>/…`) so the correct bucket is always
resolvable from the key alone (`app/storage.py`).

## Storage routing

- `settings.region_buckets` maps each region to its bucket, e.g.
  `{"us": "firewallguard-tsr-us", "eu": "firewallguard-tsr-eu", ...}`.
- Buckets are created in the matching AWS region with Block Public Access, default
  encryption (SSE-KMS), versioning and lifecycle rules aligned to the retention
  policy.
- A customer's data never leaves its region: uploads, pulls and report downloads
  all route through `_bucket_for_region(org.region)`.

## Database options

Two supported topologies, chosen per compliance posture:

1. **Separate database per region (recommended for strict residency).**
   Deploy an independent app + DB + worker stack per region behind a global
   router that directs each tenant to its regional stack by `region`. No tenant
   row ever crosses a regional boundary. Strongest isolation; higher operational
   cost.

2. **Single global database with row-level enforcement.**
   One database with `organization_id`/`region` on every row and row-level security
   (Postgres RLS) so queries are constrained to the caller's organization and
   region. Lower cost; residency depends on correct RLS policies and is generally
   acceptable for metadata while keeping the *content* (TSRs/reports) regional in
   S3, which this implementation already does.

## Region selection at sign-up

- `GET /api/v1/regions` returns the available regions and the default.
- The sign-up / organization-settings flow sets `Organization.region`
  (`PATCH /api/v1/organization`). Region is presented at sign-up and is
  immutable thereafter without a documented data-migration process.

## Changing an organization's region

Region changes require migrating existing objects between buckets and is an
operator-run, audited procedure (export from the source-region bucket, import to
the destination, update keys, verify, then flip `Organization.region`). It is not
a self-serve action.
