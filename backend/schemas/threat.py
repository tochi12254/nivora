from pydantic import BaseModel, Field, IPvAnyAddress
from datetime import datetime
from typing import Optional
from enum import Enum


class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(str, Enum):
    MALWARE = "malware"
    INTRUSION = "intrusion"
    DOS = "dos"
    SCAN = "scan"
    EXPLOIT = "exploit"
    POLICY_VIOLATION = "policy_violation"


class ThreatBase(BaseModel):
    type: ThreatType
    severity: ThreatSeverity
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress
    description: str
    raw_data: Optional[str] = None


class ThreatCreate(ThreatBase):
    pass


class ThreatUpdate(BaseModel):
    status: Optional[str] = None
    resolved: Optional[bool] = None
    notes: Optional[str] = None


class ThreatInDB(ThreatBase):
    id: int
    timestamp: datetime
    status: str = "new"
    resolved: bool = False
    resolved_at: Optional[datetime] = None

    class Config:
        orm_mode = True


class ThreatResponse(ThreatInDB):
    pass


class ThreatStats(BaseModel):
    total: int
    by_type: dict[str, int]
    by_severity: dict[str, int]
    last_24h: int
