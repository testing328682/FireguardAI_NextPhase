Add a new detection rule to the catalog. I will provide the rule details. For each rule:

1. Determine which catalog file it belongs to (catalog.py for core rules, catalog_parity.py for per-object rules, catalog_info.py for informational).
2. Write the rule function using the @registry.rule decorator pattern.
3. The rule must be evidence-gated: only fire when the TSR snapshot explicitly shows the condition.
4. For per-object rules, emit one Finding per affected object with object_name, object_type, and object_detail populated.
5. Include compliance mappings as Dict[str, List[str]] (e.g. {"PCI DSS 4.0": ["1.2"], "CIS v8": ["4"]}).
6. Set likelihood, impact, and exposure (1-5 each) for the exploitability calculation.
7. Write a test in tests/test_engine.py that verifies the rule fires on the reference TSR (or explain why it would not fire on that specific device).
8. Run the test suite to confirm nothing breaks.
