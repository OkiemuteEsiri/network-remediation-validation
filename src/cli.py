from __future__ import annotations

import argparse
from pathlib import Path

from .io_utils import load_cases
from .reporting import render_markdown
from .validator import assess_all


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate network-security remediation evidence from an offline JSON dataset.")
    parser.add_argument("input", help="Path to remediation cases JSON")
    parser.add_argument("--report", default="reports/generated-report.md", help="Markdown report output path")
    args = parser.parse_args()

    cases = load_cases(args.input)
    findings = assess_all(cases)
    report = render_markdown(cases, findings)
    output = Path(args.report)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    print(f"Assessed {len(cases)} remediation cases; identified {len(findings)} validation findings.")
    print(f"Report written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
