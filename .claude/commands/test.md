Run the full test suite and report results:

1. cd backend && python -m pytest tests/ -v --tb=short
2. If any test fails, read the traceback, identify the root cause, fix it, and re-run.
3. After all tests pass, run: python -m firewallguard.cli analyze (against any available TSR) to confirm the pipeline works end-to-end.
4. Check that all Python files compile: python -m py_compile $(find . -name '*.py' -not -path '*/__pycache__/*')
5. Report: total tests, passed, failed, and any warnings.
