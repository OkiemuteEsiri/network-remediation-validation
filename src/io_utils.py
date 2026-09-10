from __future__ import annotations

import json
from pathlib import Path

from .models import RemediationCase, parse_utc


def load_cases(path: str | Path) -> list[RemediationCase]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("input must be a JSON list")

    cases: list[RemediationCase] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError("each remediation case must be an object")
        case_id = str(item.get("case_id", "")).strip()
        if case_id in seen:
            raise ValueError(f"duplicate case_id: {case_id}")
        seen.add(case_id)

        cases.append(
            RemediationCase(
                case_id=case_id,
                asset=str(item.get("asset", "")).strip(),
                owner=str(item.get("owner", "")).strip(),
                control_type=str(item.get("control_type", "")).strip(),
                severity=str(item.get("severity", "")).lower().strip(),
                status=str(item.get("status", "")).lower().strip(),
                source_zone=str(item.get("source_zone", "")).strip(),
                destination_zone=str(item.get("destination_zone", "")).strip(),
                source_cidr=str(item.get("source_cidr", "")).strip(),
                destination_cidr=str(item.get("destination_cidr", "")).strip(),
                service=str(item.get("service", "")).strip(),
                opened_at=parse_utc(str(item["opened_at"])),
                implemented_at=parse_utc(str(item["implemented_at"])) if item.get("implemented_at") else None,
                validated_at=parse_utc(str(item["validated_at"])) if item.get("validated_at") else None,
                validation_evidence=tuple(str(x) for x in item.get("validation_evidence", [])),
                expected_state=str(item.get("expected_state", "")).strip(),
                observed_state=str(item.get("observed_state", "")).strip(),
                exception_expiry=parse_utc(str(item["exception_expiry"])) if item.get("exception_expiry") else None,
            )
        )
    return cases
