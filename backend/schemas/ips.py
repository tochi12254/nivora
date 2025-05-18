from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field, validator
from ipaddress import IPv4Address, IPv6Address, ip_address, ip_network
from schemas.base import SeverityLevel, Protocol


class IPSAction(str, Enum):
    """Possible actions for IPS"""

    BLOCK = "block"
    ALLOW = "allow"
    THROTTLE = "throttle"
    QUARANTINE = "quarantine"
    REDIRECT = "redirect"


class IPSMode(str, Enum):
    """Operational modes for IPS"""

    PREVENTION = "prevention"
    DETECTION = "detection"
    LEARNING = "learning"


class IPSConfigResponse(BaseModel):
    """Response model for IPS configuration"""

    enabled: bool = Field(..., description="Whether IPS is currently enabled")
    mode: IPSMode = Field(..., description="Operational mode")
    default_action: IPSAction = Field(
        ..., description="Default action for unmatched traffic"
    )
    rule_count: int = Field(..., description="Number of loaded rules")
    last_updated: datetime = Field(
        ..., description="Last configuration update timestamp"
    )
    auto_block_enabled: bool = Field(..., description="Whether auto-block is enabled")
    auto_block_threshold: int = Field(
        ..., description="Number of alerts before auto-block", ge=1
    )
    auto_block_window: int = Field(
        ..., description="Time window for auto-block (minutes)", ge=1
    )
    performance: Dict[str, float] = Field(
        ...,
        description="Performance metrics",
        example={
            "avg_processing_time": 0.0015,
            "throughput": 2500.5,
            "packets_processed": 3000000,
        },
    )

    class Config:
        json_schema_extra = {
            "example": {
                "enabled": True,
                "mode": "prevention",
                "default_action": "block",
                "rule_count": 85,
                "last_updated": "2023-07-15T14:30:00Z",
                "auto_block_enabled": True,
                "auto_block_threshold": 5,
                "auto_block_window": 10,
                "performance": {
                    "avg_processing_time": 0.0015,
                    "throughput": 2500.5,
                    "packets_processed": 3000000,
                },
            }
        }


class IPSBlockIPRequest(BaseModel):
    """Request model for blocking an IP address"""

    ip_address: str = Field(..., description="IP address to block")
    duration_seconds: Optional[int] = Field(
        None, description="Duration of block in seconds (None for permanent)", ge=1
    )
    reason: str = Field(..., description="Reason for blocking")
    severity: SeverityLevel = Field(..., description="Severity level")
    source: str = Field(..., description="Source of the block request (manual/auto)")
    related_threat_id: Optional[str] = Field(
        None, description="Related threat ID if auto-blocked"
    )

    @validator("ip_address")
    def validate_ip_address(cls, v):
        try:
            ip_address(v)
        except ValueError:
            try:
                ip_network(v)
            except ValueError:
                raise ValueError("Must be valid IP address or CIDR block")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "ip_address": "192.168.1.100",
                "duration_seconds": 3600,
                "reason": "Multiple SQL injection attempts",
                "severity": "high",
                "source": "manual",
                "related_threat_id": "threat-12345",
            }
        }


class IPSActionResponse(BaseModel):
    """Response model for IPS actions"""

    action: IPSAction = Field(..., description="Action taken")
    target: str = Field(..., description="Target of the action (IP/port/etc.)")
    status: str = Field(..., description="Status of the action")
    timestamp: datetime = Field(..., description="Time action was taken")
    duration: Optional[int] = Field(
        None, description="Duration of action in seconds (if temporary)"
    )
    message: Optional[str] = Field(None, description="Additional context")
    rule_id: Optional[str] = Field(None, description="Related rule ID")

    class Config:
        json_schema_extra = {
            "example": {
                "action": "block",
                "target": "192.168.1.100",
                "status": "success",
                "timestamp": "2023-07-15T14:25:00Z",
                "duration": 3600,
                "message": "Blocked due to multiple SQL injection attempts",
                "rule_id": "rule-12345",
            }
        }


class IPSRuleResponse(BaseModel):
    """Response model for IPS rules"""

    id: str = Field(..., description="Unique rule ID")
    name: str = Field(..., description="Rule name")
    description: str = Field(..., description="Rule description")
    action: IPSAction = Field(..., description="Action to take")
    severity: SeverityLevel = Field(..., description="Severity level")
    source: str = Field(..., description="Source IP/CIDR")
    destination: str = Field(..., description="Destination IP/CIDR")
    protocol: Protocol = Field(..., description="Network protocol")
    source_port: Optional[str] = Field(None, description="Source port or range")
    destination_port: Optional[str] = Field(
        None, description="Destination port or range"
    )
    application: Optional[str] = Field(None, description="Application/service name")
    enabled: bool = Field(..., description="Whether rule is enabled")
    is_system: bool = Field(..., description="Whether rule is system-generated")
    created_at: datetime = Field(..., description="Rule creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    match_count: int = Field(0, description="Number of times rule has matched")
    last_match: Optional[datetime] = Field(None, description="Last match timestamp")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "ips-rule-123",
                "name": "Block SQL Injection",
                "description": "Blocks SQL injection attempts to web servers",
                "action": "block",
                "severity": "high",
                "source": "any",
                "destination": "10.0.0.5",
                "protocol": "tcp",
                "source_port": None,
                "destination_port": "80",
                "application": "http",
                "enabled": True,
                "is_system": False,
                "created_at": "2023-07-15T12:00:00Z",
                "updated_at": "2023-07-15T12:00:00Z",
                "match_count": 8,
                "last_match": "2023-07-15T14:25:00Z",
            }
        }


class IPSStatsResponse(BaseModel):
    """Response model for IPS statistics"""

    time_range: str = Field(..., description="Time range for statistics")
    total_actions: int = Field(..., description="Total actions taken")
    actions_by_type: Dict[IPSAction, int] = Field(
        ..., description="Count of actions by type"
    )
    blocked_ips: int = Field(..., description="Total unique IPs blocked")
    top_blocked_ips: List[Dict[str, int]] = Field(
        ...,
        description="Top blocked IPs by count",
        example=[{"ip": "192.168.1.100", "count": 8}],
    )
    top_target_ips: List[Dict[str, int]] = Field(
        ..., description="Top protected IPs by action count"
    )
    protocol_distribution: Dict[Protocol, int] = Field(
        ..., description="Action distribution by protocol"
    )
    rule_effectiveness: List[Dict[str, int]] = Field(
        ...,
        description="Top rules by action count",
        example=[{"rule_id": "ips-rule-123", "count": 12}],
    )
    false_positives: int = Field(..., description="Number of false positives detected")
    start_time: datetime = Field(..., description="Start of time range")
    end_time: datetime = Field(..., description="End of time range")

    class Config:
        json_schema_extra = {
            "example": {
                "time_range": "24h",
                "total_actions": 85,
                "actions_by_type": {
                    "block": 42,
                    "allow": 30,
                    "throttle": 10,
                    "quarantine": 3,
                },
                "blocked_ips": 15,
                "top_blocked_ips": [
                    {"ip": "192.168.1.100", "count": 8},
                    {"ip": "10.0.0.15", "count": 5},
                ],
                "top_target_ips": [
                    {"ip": "10.0.0.5", "count": 12},
                    {"ip": "10.0.0.10", "count": 8},
                ],
                "protocol_distribution": {"tcp": 50, "http": 25, "udp": 10},
                "rule_effectiveness": [
                    {"rule_id": "ips-rule-123", "count": 12},
                    {"rule_id": "ips-rule-456", "count": 8},
                ],
                "false_positives": 2,
                "start_time": "2023-07-14T14:30:00Z",
                "end_time": "2023-07-15T14:30:00Z",
            }
        }


class IPSTopThreatsResponse(BaseModel):
    """Response model for top threats prevented by IPS"""

    source_ip: str = Field(..., description="Source IP address")
    threat_type: str = Field(..., description="Type of threat detected")
    count: int = Field(..., description="Number of times threat was detected")
    first_detected: datetime = Field(..., description="First detection timestamp")
    last_detected: datetime = Field(..., description="Last detection timestamp")
    action_taken: IPSAction = Field(..., description="Action taken against threat")
    severity: SeverityLevel = Field(..., description="Severity level")
    is_internal: bool = Field(..., description="Whether source is internal")
    geo_info: Optional[Dict] = Field(
        None,
        description="Geolocation info for source IP",
        example={
            "country": "US",
            "city": "New York",
            "asn": "AS15169",
            "org": "Google LLC",
        },
    )

    class Config:
        json_schema_extra = {
            "example": {
                "source_ip": "192.168.1.100",
                "threat_type": "SQL Injection Attempt",
                "count": 8,
                "first_detected": "2023-07-15T10:15:00Z",
                "last_detected": "2023-07-15T14:25:00Z",
                "action_taken": "block",
                "severity": "high",
                "is_internal": True,
                "geo_info": None,
            }
        }
