from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Iterable

from .models import RemediationCase, ValidationFinding

SEVERITY_WEIGHT = {"critical": 35, "high": 25, "medium": 15, "low": 5}
ATTACK_CONTEXT = {
    "firewall": ("T1190", "T1133"),
    "segmentation": ("T1021", "T1210"),
    "remote_access": ("T1133", "T1078"),
    "tls": ("T1557",),
    "dns": ("T1071.004",),
    "network_service": ("T1210",),
}


def _finding_id(case_id: str, title: str) -> str:
    digest = hashlib.sha256(f"{case_id}:{title}".encode()).hexdigest()[:12]
    return f"NRV-{digest.upper()}"


def _score(case: RemediationCase, rationale: list[str], now: datetime) -> int:
    score = SEVERITY_WEIGHT[case.severity]
    if case.status == "open":
        score += 25
    elif case.status == "implemented":
        score += 15
    elif case.status == "accepted":
        score += 10
    if not case.owner.strip():
        score += 10
    if case.expected_state.strip() != case.observed_state.strip():
        score += 20
    if case.status == "implemented" and not case.validation_evidence:
        score += 10
    if case.exception_expiry and case.exception_expiry < now:
        score += 15
    return min(score, 100)


def assess_case(case: RemediationCase, now: datetime | None = None) -> list[ValidationFinding]:
    now = now or datetime.now(timezone.utc)
    findings: list[ValidationFinding] = []

    def add(title: str, rationale: list[str], remediation: str, validation: str) -> None:
        findings.append(
            ValidationFinding(
                finding_id=_finding_id(case.case_id, title),
                case_id=case.case_id,
                severity=case.severity,
                score=_score(case, rationale, now),
                title=title,
                rationale=tuple(rationale),
                attack_context=ATTACK_CONTEXT.get(case.control_type, ()),
                remediation=remediation,
                validation_required=validation,
            )
        )

    if not case.owner.strip():
        add(
            "Missing remediation owner",
            ["No accountable owner is assigned to the remediation case."],
            "Assign a named control owner and remediation due date.",
            "Confirm ownership is recorded and acknowledged.",
        )

    if case.status == "implemented" and not case.validation_evidence:
        add(
            "Implementation lacks validation evidence",
            ["The control is marked implemented but has no independent validation evidence."],
            "Perform a post-change control test and retain evidence.",
            "Record dated evidence showing the expected control state is enforced.",
        )

    if case.expected_state.strip() != case.observed_state.strip():
        add(
            "Observed state does not match target state",
            [f"Expected: {case.expected_state}", f"Observed: {case.observed_state}"],
            "Correct the network control so the observed state matches the approved target.",
            "Re-run the validation procedure and compare expected versus observed state.",
        )

    if case.status == "validated" and case.expected_state.strip() == case.observed_state.strip():
        return findings

    if case.status == "accepted" and case.exception_expiry and case.exception_expiry < now:
        add(
            "Risk acceptance has expired",
            ["The documented exception expiry date has passed."],
            "Reassess the risk; remediate the control or obtain a new approved exception.",
            "Verify the exception owner, approval, compensating controls, and new expiry date.",
        )

    return findings


def assess_all(cases: Iterable[RemediationCase], now: datetime | None = None) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    for case in cases:
        findings.extend(assess_case(case, now=now))
    return sorted(findings, key=lambda item: (-item.score, item.case_id, item.finding_id))
