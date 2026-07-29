# FirewallGuard AI — Web App

A single-page web interface for FirewallGuard AI. Upload a SonicWall Tech
Support Report (TSR), watch the analysis run, then view findings, attack paths
and firmware intelligence on screen and download the executive PDF, technical
PDF, CSV or JSON.

## Stack

React 18 + TypeScript, built with Vite, styled with Tailwind. It talks to the
FastAPI backend in `../backend` over the `/api/v1` endpoints.

## Develop

```bash
npm install
npm run dev          # http://localhost:5173, proxies /api to localhost:8000
```

Run the backend separately (see `../backend`), or click **Explore with sample
data** on the sign-in screen to view a real NSa 3700 analysis without a backend.

## Build

```bash
npm run build        # outputs to dist/
npm run preview      # serve the production build locally
```

## Run the whole stack

From the repository root:

```bash
docker compose up --build
# Web app:  http://localhost:8080
# API docs: http://localhost:8000/docs
```

Sign in, and the app creates a default customer for you on first load so you
can upload immediately. Uploading a TSR creates (or reuses, by serial) a device,
runs the analysis pipeline, and shows the report when it completes.

## What the screens do

- **Sign in** — authenticates against the backend, or enters sample mode.
- **Upload** — drag-and-drop or browse for a `.wri`/`.txt` TSR; a progress
  indicator tracks upload → analyze → report.
- **Posture** — the score gauge and grade, device identity, severity
  distribution, and the four report downloads.
- **Attack paths** — correlated multi-stage chains with kill-chain narration.
- **PSIRT advisories** — firmware vulnerabilities matched to the running build,
  with CVEs, CVSS and the fixed version.
- **Findings** — the full, filterable table. Each row names the affected object
  (access rule, address object, VPN policy, etc.) and expands to show evidence,
  impact, remediation, verification and compliance mappings.

## Notes

- Tokens are kept in `sessionStorage` and refreshed automatically on expiry.
- Sample mode loads `src/demo-analysis.json` (a real analysis with the snapshot
  removed); report downloads require a live backend.
