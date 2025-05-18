from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, validator
from ipaddress import IPv4Address, IPv6Address, ip_address
from schemas.base import SeverityLevel, Protocol

class IDSRuleAction(str, Enum):
    """Possible actions for IDS rules"""
    ALERT = "alert"
    LOG = "log"
    DROP = "drop"
    BLOCK = "block"
    THROTTLE = "throttle"

class IDSRuleProtocol(str, Enum):
    """Protocols supported by IDS rules"""
    ANY = "any"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    HTTP = "http"
    DNS = "dns"
    SSH = "ssh"
    SMTP = "smtp"

class IDSRuleDirection(str, Enum):
    """Traffic directions for IDS rules"""
    ANY = "any"
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"

class IDSConfigResponse(BaseModel):
    """Response model for IDS configuration"""
    enabled: bool = Field(..., description="Whether IDS is currently enabled")
    mode: str = Field(..., description="Detection mode (passive/active)")
    rule_count: int = Field(..., description="Number of loaded rules")
    last_updated: datetime = Field(..., description="Last configuration update timestamp")
    signature_sources: List[str] = Field(..., description="List of signature sources")
    performance: Dict[str, float] = Field(
        ...,
        description="Performance metrics",
        example={
            "avg_processing_time": 0.0025,
            "throughput": 1250.5,
            "packets_processed": 1500000
        }
    )
    detection_stats: Dict[str, int] = Field(
        ...,
        description="Detection statistics",
        example={
            "true_positives": 42,
            "false_positives": 3,
            "false_negatives": 1
        }
    )

    class Config:
        json_schema_extra = {
            "example": {
                "enabled": True,
                "mode": "active",
                "rule_count": 125,
                "last_updated": "2023-07-15T14:30:00Z",
                "signature_sources": ["ET Open", "Emerging Threats", "Custom"],
                "performance": {
                    "avg_processing_time": 0.0025,
                    "throughput": 1250.5,
                    "packets_processed": 1500000
                },
                "detection_stats": {
                    "true_positives": 42,
                    "false_positives": 3,
                    "false_negatives": 1
                }
            }
        }

class IDSRuleCreate(BaseModel):
    """Request model for creating new IDS rules"""
    name: str = Field(..., min_length=3, max_length=100, description="Rule name")
    description: str = Field(..., min_length=10, max_length=500, description="Rule description")
    protocol: IDSRuleProtocol = Field(..., description="Protocol to match")
    direction: IDSRuleDirection = Field(..., description="Traffic direction")
    source: str = Field(
        ...,
        description="Source IP/CIDR (or 'any')",
        example="192.168.1.0/24"
    )
    destination: str = Field(
        ...,
        description="Destination IP/CIDR (or 'any')",
        example="10.0.0.5"
    )
    source_port: Optional[str] = Field(
        None,
        description="Source port or range (e.g., '80', '1000:2000')"
    )
    destination_port: Optional[str] = Field(
        None,
        description="Destination port or range"
    )
    pattern: Optional[str] = Field(
        None,
        description="Content pattern to match (regex)",
        example="(sql|select|union).*from"
    )
    action: IDSRuleAction = Field(..., description="Action to take when matched")
    severity: SeverityLevel = Field(..., description="Severity level")
    enabled: bool = Field(True, description="Whether rule is enabled")
    threshold: Optional[int] = Field(
        None,
        description="Number of matches before triggering",
        ge=1
    )
    window: Optional[int] = Field(
        None,
        description="Time window for threshold (seconds)",
        ge=1
    )

    @validator('source', 'destination')
    def validate_ip_or_any(cls, v):
        if v.lower() != 'any':
            try:
                ip_address(v)
            except ValueError:
                try:
                    ip_network(v)
                except ValueError:
                    raise ValueError("Must be valid IP, CIDR, or 'any'")
        return v

    @validator('source_port', 'destination_port')
    def validate_port_or_range(cls, v):
        if v is None:
            return v
        if ':' in v:
            parts = v.split(':')
            if len(parts) != 2:
                raise ValueError("Port range must be in format 'start:end'")
            start, end = parts
            if not start.isdigit() or not end.isdigit():
                raise ValueError("Ports must be numeric")
            if int(start) > int(end):
                raise ValueError("Start port must be <= end port")
        elif not v.isdigit():
            raise ValueError("Port must be numeric")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "name": "SQL Injection Detection",
                "description": "Detects common SQL injection patterns in HTTP traffic",
                "protocol": "http",
                "direction": "inbound",
                "source": "any",
                "destination": "10.0.0.5",
                "source_port": None,
                "destination_port": "80",
                "pattern": "(union\\s+select|1=1|sleep\\(\\d+\\))",
                "action": "block",
                "severity": "high",
                "enabled": True,
                "threshold": 5,
                "window": 60
            }
        }

class IDSRuleResponse(BaseModel):
    """Response model for IDS rules"""
    id: str = Field(..., description="Unique rule ID")
    name: str = Field(..., description="Rule name")
    description: str = Field(..., description="Rule description")
    protocol: IDSRuleProtocol = Field(..., description="Protocol to match")
    direction: IDSRuleDirection = Field(..., description="Traffic direction")
    source: str = Field(..., description="Source IP/CIDR")
    destination: str = Field(..., description="Destination IP/CIDR")
    source_port: Optional[str] = Field(None, description="Source port or range")
    destination_port: Optional[str] = Field(None, description="Destination port or range")
    action: IDSRuleAction = Field(..., description="Action to take when matched")
    severity: SeverityLevel = Field(..., description="Severity level")
    enabled: bool = Field(..., description="Whether rule is enabled")
    created_at: datetime = Field(..., description="Rule creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    match_count: int = Field(0, description="Number of times rule has matched")
    last_match: Optional[datetime] = Field(None, description="Last match timestamp")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "rule-12345",
                "name": "SQL Injection Detection",
                "description": "Detects common SQL injection patterns in HTTP traffic",
                "protocol": "http",
                "direction": "inbound",
                "source": "any",
                "destination": "10.0.0.5",
                "source_port": None,
                "destination_port": "80",
                "action": "block",
                "severity": "high",
                "enabled": True,
                "created_at": "2023-07-15T12:00:00Z",
                "updated_at": "2023-07-15T12:00:00Z",
                "match_count": 8,
                "last_match": "2023-07-15T14:25:00Z"
            }
        }

class IDSThreatResponse(BaseModel):
    """Response model for detected threats"""
    id: str = Field(..., description="Unique threat ID")
    timestamp: datetime = Field(..., description="Detection timestamp")
    rule_id: Optional[str] = Field(None, description="ID of matching rule")
    rule_name: Optional[str] = Field(None, description="Name of matching rule")
    threat_type: str = Field(..., description="Type of threat detected")
    severity: SeverityLevel = Field(..., description="Severity level")
    source_ip: Optional[str] = Field(None, description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    source_port: Optional[int] = Field(None, description="Source port")
    destination_port: Optional[int] = Field(None, description="Destination port")
    protocol: Protocol = Field(..., description="Network protocol")
    packet_size: int = Field(..., description="Packet size in bytes")
    packet_summary: str = Field(..., description="Brief packet summary")
    raw_data: Optional[str] = Field(None, description="Raw packet data (truncated)")
    is_internal: bool = Field(..., description="Whether source is internal")
    geo_info: Optional[Dict] = Field(
        None,
        description="Geolocation info for source IP",
        example={
            "country": "US",
            "city": "New York",
            "asn": "AS15169",
            "org": "Google LLC"
        }
    )

    class Config:
        json_schema_extra = {
            "example": {
                "id": "threat-67890",
                "timestamp": "2023-07-15T14:25:00Z",
                "rule_id": "rule-12345",
                "rule_name": "SQL Injection Detection",
                "threat_type": "SQL Injection Attempt",
                "severity": "high",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.5",
                "source_port": 54321,
                "destination_port": 80,
                "protocol": "tcp",
                "packet_size": 512,
                "packet_summary": "HTTP GET /login.php?user=admin'--",
                "is_internal": True,
                "geo_info": None
            }
        }

class IDSStatsResponse(BaseModel):
    """Response model for IDS statistics"""
    time_range: str = Field(..., description="Time range for statistics")
    total_threats: int = Field(..., description="Total threats detected")
    threats_by_severity: Dict[SeverityLevel, int] = Field(
        ...,
        description="Count of threats by severity level"
    )
    threats_by_type: Dict[str, int] = Field(
        ...,
        description="Count of threats by type"
    )
    top_source_ips: List[Dict[str, int]] = Field(
        ...,
        description="Top source IPs by threat count",
        example=[{"ip": "192.168.1.100", "count": 8}]
    )
    top_destination_ips: List[Dict[str, int]] = Field(
        ...,
        description="Top destination IPs by threat count"
    )
    protocol_distribution: Dict[Protocol, int] = Field(
        ...,
        description="Threat distribution by protocol"
    )
    rule_effectiveness: List[Dict[str, int]] = Field(
        ...,
        description="Top rules by threat detection count",
        example=[{"rule_id": "rule-12345", "count": 12}]
    )
    false_positives: int = Field(
        ...,
        description="Number of false positives detected"
    )
    start_time: datetime = Field(..., description="Start of time range")
    end_time: datetime = Field(..., description="End of time range")

    class Config:
        json_schema_extra = {
            "example": {
                "time_range": "24h",
                "total_threats": 42,
                "threats_by_severity": {
                    "critical": 5,
                    "high": 15,
                    "medium": 12,
                    "low": 10
                },
                "threats_by_type": {
                    "Port Scan": 15,
                    "SQL Injection": 8,
                    "DDoS": 5,
                    "Malware": 10,
                    "Other": 4
                },
                "top_source_ips": [
                    {"ip": "192.168.1.100", "count": 8},
                    {"ip": "10.0.0.15", "count": 5}
                ],
                "top_destination_ips": [
                    {"ip": "10.0.0.5", "count": 12},
                    {"ip": "10.0.0.10", "count": 8}
                ],
                "protocol_distribution": {
                    "tcp": 30,
                    "http": 8,
                    "udp": 4
                },
                "rule_effectiveness": [
                    {"rule_id": "rule-12345", "count": 12},
                    {"rule_id": "rule-67890", "count": 8}
                ],
                "false_positives": 3,
                "start_time": "2023-07-14T14:30:00Z",
                "end_time": "2023-07-15T14:30:00Z"
            }
        }