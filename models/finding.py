from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    @property
    def score_weight(self) -> int:
        weights = {
            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 8,
            "LOW": 3,
            "INFORMATIONAL": 0
        }
        return weights.get(self.value, 0)


@dataclass
class Finding:
    service: str
    resource_id: str
    severity: str
    title: str
    description: str
    remediation: str
    compliance_benchmark: str = "AWS Well-Architected Security Pillar"
    resource_type: Optional[str] = None
    region: str = "us-east-1"
    timestamp: Optional[str] = None
    finding_id: Optional[str] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.finding_id:
            self.finding_id = f"CS-{uuid.uuid4().hex[:8].upper()}"
        if not self.resource_type:
            self.resource_type = f"AWS::{self.service.upper()}::Resource"

    def to_dict(self) -> dict:
        return asdict(self)