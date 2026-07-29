Check the current state of the project and report:

1. Read FIREWALLGUARD-AI-SPEC.md for the full feature list.
2. Scan the codebase and determine which Phase 1/2/3/4 deliverables are implemented vs missing.
3. List the backend API endpoints that exist (grep for @router decorators).
4. List the frontend routes that exist (grep for Route or path definitions in App.tsx or router config).
5. Count active detection rules (import the registry from the engine and print len(registry.active_rules())).
6. Run the test suite and report pass/fail count.
7. Check if Alembic is initialized and migrations are up to date.
8. Produce a summary table: Feature | Status (Done/Partial/Not Started) | Notes.
