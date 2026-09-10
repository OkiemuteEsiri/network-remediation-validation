from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import ip_network

ALLOWED_STATUSES = {"open", "implemented", "validated", "accepted"}
ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}
ALLOWED_CONTROL_TYPES = {"firewall", "segmentation", "remote_access", "tls", "dns", "network_service"}


def parse_utc(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class RemediationCase:
    case_id: str
    asset: str
    owner: str
    control_type: str
    severity: str
    status: str
    source_zone: str
    destination_zone: str
    source_cidr: str
    destination_cidr: str
    service: str
    opened_at: datetime
    implemented_at: datetime | None
    validated_at: datetime | None
    validation_evidence: tuple[str, ...]
    expected_state: str
    observed_state: str
    exception_expiry: datetime | None = None

    def __post_init__(self) -> None:
        if not self.case_id.strip() or not self.asset.strip():
            raise ValueError("case_id and asset are required")
        if self.severity not in ALLOWED_SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity}")
        if self.status not in ALLOWED_STATUSES:
            raise ValueError(f"invalid status: {self.status}")
        if self.control_type not in ALLOWED_CONTROL_TYPES:
            raise ValueError(f"invalid control_type: {self.control_type}")
        ip_network(self.source_cidr, strict=False)
        ip_network(self.destination_cidr, strict=False)
        if self.status == "validated" and not self.validation_evidence:
            raise ValueError("validated cases require evidence")
        if self.validated_at and not self.implemented_at:
            raise ValueError("validation cannot precede implementation lifecycle")
        if self.implemented_at and self.implemented_at < self.opened_at:
            raise ValueError("implemented_at cannot be before opened_at")
        if self.validated_at and self.implemented_at and self.validated_at < self.implemented_at:
            raise ValueError("validated_at cannot be before implemented_at")


@dataclass(frozen=True)
class ValidationFinding:
    finding_id: str
    case_id: str
    severity: str
    score: int
    title: str
    rationale: tuple[str, ...]
    attack_context: tuple[str, ...]
    remediation: str
    validation_required: str
