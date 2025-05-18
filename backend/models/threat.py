from sqlalchemy import Column, Integer, String, Enum, DateTime, Boolean, Text, Index
from sqlalchemy.sql import func
from app.database import Base
from enum import Enum as PyEnum


class ThreatSeverity(str, PyEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(str, PyEnum):
    MALWARE = "malware"
    INTRUSION = "intrusion"
    DOS = "dos"
    SCAN = "scan"
    EXPLOIT = "exploit"
    POLICY_VIOLATION = "policy_violation"


class Threat(Base):
    __tablename__ = "threats"
    __table_args__ = (
        Index("ix_threat_timestamp", "timestamp"),
        Index("ix_threat_source_ip", "source_ip"),
        Index("ix_threat_type_severity", "type", "severity"),
    )
    id = Column(Integer, primary_key=True, index=True)
    type = Column(Enum(ThreatType), nullable=False)
    severity = Column(Enum(ThreatSeverity), nullable=False)
    source_ip = Column(String(45), nullable=False)
    destination_ip = Column(String(45), nullable=False)
    description = Column(String(500), nullable=False)
    raw_data = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String(50), default="new")
    resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<Threat {self.id} - {self.type} ({self.severity})>"
