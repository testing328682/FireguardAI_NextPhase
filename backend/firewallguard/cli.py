"""FirewallGuard AI command-line interface.

Runs the full analysis pipeline against one or two TSR files without requiring
the database, broker or web stack. Useful for local evaluation, CI smoke tests
and generating sample reports.

Usage:
    python -m firewallguard.cli analyze TSR.wri [--out OUTDIR]
    python -m firewallguard.cli drift OLD_TSR.wri NEW_TSR.wri
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from .pipeline import analyze_text
from .analytics.drift import detect_drift
from .tsr.parser import parse_tsr
from .report import generator as gen


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def cmd_analyze(args: argparse.Namespace) -> int:
    text = _read(args.tsr)
    analysis = analyze_text(text, os.path.basename(args.tsr))
    score = analysis["score"]
    print(f"Device : {analysis['device'].get('model')} "
          f"(serial {analysis['device'].get('serial')})")
    print(f"Firmware: {analysis['device'].get('firmware')}")
    print(f"Score  : {score['score']:.0f}/100  Grade {score['grade']} "
          f"({score['grade_label']})")
    sev = score["severity_counts"]
    print(f"Findings: {analysis['finding_count']} "
          f"(Critical {sev.get('Critical',0)}, High {sev.get('High',0)}, "
          f"Medium {sev.get('Medium',0)}, Low {sev.get('Low',0)}, Info {sev.get('Info',0)})")
    print(f"Attack paths: {len(analysis['attack_paths'])}")
    for ap in analysis["attack_paths"]:
        print(f"  - {ap['path_id']} {ap['name']} [{ap['severity']}]")

    if args.out:
        os.makedirs(args.out, exist_ok=True)
        gen.build_executive_pdf(analysis, os.path.join(args.out, "executive.pdf"))
        gen.build_technical_pdf(analysis, os.path.join(args.out, "technical.pdf"))
        gen.export_findings_csv(analysis, os.path.join(args.out, "findings.csv"))
        gen.export_json(analysis, os.path.join(args.out, "analysis.json"))
        print(f"\nReports written to {args.out}")
    return 0


def cmd_drift(args: argparse.Namespace) -> int:
    prev = parse_tsr(_read(args.old), os.path.basename(args.old))
    curr = parse_tsr(_read(args.new), os.path.basename(args.new))
    drift = detect_drift(prev, curr)
    print(f"Drift alerts: {drift['alert_count']}")
    print(f"By severity : {drift['severity_counts']}")
    for a in drift["alerts"][:40]:
        print(f"  [{a['severity']}] {a['category']}: {a['title']} - {a['detail']}")
    if args.json:
        print(json.dumps(drift, indent=2, default=str))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="firewallguard",
                                     description="FirewallGuard AI analysis CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_an = sub.add_parser("analyze", help="Analyze a single TSR")
    p_an.add_argument("tsr")
    p_an.add_argument("--out", help="Directory to write reports into")
    p_an.set_defaults(func=cmd_analyze)

    p_dr = sub.add_parser("drift", help="Compare two TSRs for configuration drift")
    p_dr.add_argument("old")
    p_dr.add_argument("new")
    p_dr.add_argument("--json", action="store_true", help="Also print full JSON")
    p_dr.set_defaults(func=cmd_drift)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
