from __future__ import annotations

from collections import Counter
from .models import RemediationCase, ValidationFinding


def portfolio_metrics(cases: list[RemediationCase], findings: list[ValidationFinding]) -> dict[str, object]:
    status_counts = Counter(case.status for case in cases)
    severity_counts = Counter(f.severity for f in findings)
    validated = status_counts.get("validated", 0)
    total = len(cases)
    return {
        "cases": total,
        "validated_cases": validated,
        "validation_rate_pct": round((validated / total * 100) if total else 0.0, 1),
        "open_findings": len(findings),
        "critical_high_findings": severity_counts.get("critical", 0) + severity_counts.get("high", 0),
        "highest_score": max((f.score for f in findings), default=0),
        "status_counts": dict(sorted(status_counts.items())),
        "finding_severity_counts": dict(sorted(severity_counts.items())),
    }


def render_markdown(cases: list[RemediationCase], findings: list[ValidationFinding]) -> str:
    metrics = portfolio_metrics(cases, findings)
    lines = [
        "# Network Remediation Validation Report",
        "",
        "## Executive summary",
        "",
        f"- Remediation cases assessed: **{metrics['cases']}**",
        f"- Cases independently validated: **{metrics['validated_cases']}**",
        f"- Validation rate: **{metrics['validation_rate_pct']}%**",
        f"- Open validation findings: **{metrics['open_findings']}**",
        f"- Critical/high validation findings: **{metrics['critical_high_findings']}**",
        f"- Highest residual-risk score: **{metrics['highest_score']} / 100**",
        "",
        "## Validation findings",
        "",
    ]
    if not findings:
        lines.append("No validation gaps were identified in the supplied synthetic dataset.")
    for finding in findings:
        lines.extend([
            f"### {finding.finding_id} — {finding.title}",
            f"- Case: `{finding.case_id}`",
            f"- Severity: **{finding.severity.title()}**",
            f"- Residual-risk score: **{finding.score}/100**",
            f"- ATT&CK context: {', '.join(finding.attack_context) or 'N/A'}",
            "- Rationale:",
            *[f"  - {item}" for item in finding.rationale],
            f"- Remediation: {finding.remediation}",
            f"- Required validation: {finding.validation_required}",
            "",
        ])
    lines.extend([
        "## Governance note",
        "",
        "Implementation is not equivalent to closure. A network security change is treated as validated only when the intended state is independently re-tested and evidence is retained. ATT&CK mappings provide threat context; they are not evidence that a technique was executed or that compromise occurred.",
    ])
    return "\n".join(lines) + "\n"
