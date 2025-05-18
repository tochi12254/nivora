from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from enum import Enum


class TimeRange(str, Enum):
    """Time range options for dashboard queries"""

    LAST_1H = "1h"
    LAST_24H = "24h"
    LAST_7D = "7d"
    LAST_30D = "30d"


class Resolution(str, Enum):
    """Timeline resolution options"""

    MINUTE_1 = "1m"
    MINUTES_5 = "5m"
    MINUTES_15 = "15m"
    HOUR_1 = "1h"
    DAY_1 = "1d"


class ThreatSeverity(str, Enum):
    """Threat severity levels"""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Protocol(str, Enum):
    """Network protocol types"""

    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    SSH = "ssh"
    OTHER = "other"


class SystemStatsResponse(BaseModel):
    """System health and resource statistics"""

    cpu_usage: float = Field(
        ..., description="Current CPU usage percentage", example=45.2
    )
    memory_usage: float = Field(
        ..., description="Current memory usage percentage", example=67.8
    )
    memory_total: int = Field(
        ..., description="Total system memory in bytes", example=17179869184
    )
    memory_used: int = Field(
        ..., description="Used system memory in bytes", example=11639193600
    )
    network_sent: int = Field(
        ..., description="Total bytes sent over network", example=102457890
    )
    network_recv: int = Field(
        ..., description="Total bytes received over network", example=204857123
    )
    disk_usage: float = Field(
        ..., description="Current disk usage percentage", example=32.1
    )
    threat_count: int = Field(..., description="Total threats detected", example=42)
    firewall_actions: int = Field(
        ..., description="Total firewall actions taken", example=128
    )
    uptime: float = Field(..., description="System uptime in seconds", example=86400.5)
    timestamp: datetime = Field(..., description="Time when stats were collected")

    class Config:
        json_schema_extra = {
            "example": {
                "cpu_usage": 45.2,
                "memory_usage": 67.8,
                "memory_total": 17179869184,
                "memory_used": 11639193600,
                "network_sent": 102457890,
                "network_recv": 204857123,
                "disk_usage": 32.1,
                "threat_count": 42,
                "firewall_actions": 128,
                "uptime": 86400.5,
                "timestamp": "2023-07-15T14:30:00Z",
            }
        }


class ThreatSummaryItem(BaseModel):
    """Threat count by type"""

    threat_type: str = Field(
        ..., description="Type of threat detected", example="Port Scan"
    )
    count: int = Field(..., description="Number of occurrences", example=15)


class SourceIPSummary(BaseModel):
    """Top source IPs generating threats"""

    ip: str = Field(..., description="Source IP address", example="192.168.1.100")
    count: int = Field(..., description="Number of threats from this IP", example=8)
    last_seen: Optional[datetime] = Field(
        None, description="Last time this IP was seen"
    )
    country: Optional[str] = Field(
        None, description="Country code if geo-IP available", example="US"
    )
    is_internal: bool = Field(
        ..., description="Whether IP is in internal network range"
    )


class ThreatSummaryResponse(BaseModel):
    """Summary of threats detected in time period"""

    time_range: TimeRange = Field(..., description="Time range covered by summary")
    total_threats: int = Field(..., description="Total threats detected", example=42)
    threats_by_type: Dict[str, int] = Field(..., description="Count of threats by type")
    top_source_ips: List[SourceIPSummary] = Field(
        ..., description="Top source IPs generating threats"
    )
    start_time: datetime = Field(..., description="Start of time range")
    end_time: datetime = Field(..., description="End of time range")

    class Config:
        json_schema_extra = {
            "example": {
                "time_range": "24h",
                "total_threats": 42,
                "threats_by_type": {
                    "Port Scan": 15,
                    "SQL Injection": 8,
                    "DDoS": 5,
                    "Malware": 10,
                    "Other": 4,
                },
                "top_source_ips": [
                    {
                        "ip": "192.168.1.100",
                        "count": 8,
                        "last_seen": "2023-07-15T14:25:00Z",
                        "country": "US",
                        "is_internal": True,
                    },
                    {
                        "ip": "45.33.12.8",
                        "count": 5,
                        "last_seen": "2023-07-15T13:40:00Z",
                        "country": "RU",
                        "is_internal": False,
                    },
                ],
                "start_time": "2023-07-14T14:30:00Z",
                "end_time": "2023-07-15T14:30:00Z",
            }
        }


class ProtocolDistribution(BaseModel):
    """Network traffic by protocol"""

    protocol: Protocol = Field(..., description="Network protocol")
    count: int = Field(..., description="Number of packets/connections")
    bytes: int = Field(..., description="Total bytes transferred")
    percentage: float = Field(..., description="Percentage of total traffic")


class TrafficSummaryResponse(BaseModel):
    """Summary of network traffic statistics"""

    active_connections: int = Field(
        ..., description="Current active network connections", example=42
    )
    known_hosts: int = Field(
        ..., description="Number of unique hosts in network", example=15
    )
    threats_detected: int = Field(
        ..., description="Threats detected in current period", example=8
    )
    protocol_distribution: Dict[Protocol, ProtocolDistribution] = Field(
        ..., description="Breakdown of traffic by protocol"
    )
    inbound_bytes: int = Field(
        ..., description="Total inbound bytes", example=102457890
    )
    outbound_bytes: int = Field(
        ..., description="Total outbound bytes", example=204857123
    )
    timestamp: datetime = Field(..., description="Time when stats were collected")

    class Config:
        json_schema_extra = {
            "example": {
                "active_connections": 42,
                "known_hosts": 15,
                "threats_detected": 8,
                "protocol_distribution": {
                    "tcp": {
                        "protocol": "tcp",
                        "count": 1200,
                        "bytes": 1024000,
                        "percentage": 65.2,
                    },
                    "http": {
                        "protocol": "http",
                        "count": 450,
                        "bytes": 512000,
                        "percentage": 22.8,
                    },
                },
                "inbound_bytes": 102457890,
                "outbound_bytes": 204857123,
                "timestamp": "2023-07-15T14:30:00Z",
            }
        }


class TimelineItem(BaseModel):
    """Activity timeline data point"""

    time: datetime = Field(..., description="Timestamp of the bucket")
    count: int = Field(..., description="Number of events in this time bucket")


class ThreatTimelineItem(TimelineItem):
    """Threat detection timeline item"""

    threat_type: str = Field(..., description="Type of threat detected")


class FirewallTimelineItem(TimelineItem):
    """Firewall action timeline item"""

    action: str = Field(..., description="Firewall action (allow/deny)")


class ActivityTimelineResponse(BaseModel):
    """Timeline of security events"""

    resolution: Resolution = Field(..., description="Time resolution of the timeline")
    threat_timeline: List[ThreatTimelineItem] = Field(
        ..., description="Timeline of threat detections"
    )
    firewall_timeline: List[FirewallTimelineItem] = Field(
        ..., description="Timeline of firewall actions"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "resolution": "1h",
                "threat_timeline": [
                    {
                        "time": "2023-07-15T10:00:00Z",
                        "count": 5,
                        "threat_type": "Port Scan",
                    },
                    {
                        "time": "2023-07-15T11:00:00Z",
                        "count": 12,
                        "threat_type": "DDoS",
                    },
                ],
                "firewall_timeline": [
                    {"time": "2023-07-15T10:00:00Z", "count": 8, "action": "deny"},
                    {"time": "2023-07-15T11:00:00Z", "count": 15, "action": "deny"},
                ],
            }
        }


class AlertSeverity(str, Enum):
    """Alert severity levels"""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertType(str, Enum):
    """Alert type categories"""

    THREAT = "threat"
    SYSTEM = "system"
    PERFORMANCE = "performance"
    CONFIGURATION = "configuration"


class Alert(BaseModel):
    """Security alert notification"""

    id: str = Field(..., description="Unique alert ID")
    timestamp: datetime = Field(..., description="Time alert was generated")
    severity: AlertSeverity = Field(..., description="Severity level")
    type: AlertType = Field(..., description="Alert category")
    title: str = Field(..., description="Brief alert title")
    description: str = Field(..., description="Detailed description")
    source: Optional[str] = Field(None, description="Source system/component")
    acknowledged: bool = Field(False, description="Whether alert has been acknowledged")
    data: Optional[Dict] = Field(None, description="Additional alert data")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "alert-12345",
                "timestamp": "2023-07-15T14:30:00Z",
                "severity": "critical",
                "type": "threat",
                "title": "DDoS Attack Detected",
                "description": "Large volume of SYN packets from multiple sources",
                "source": "IDS",
                "acknowledged": False,
                "data": {
                    "source_ips": ["192.168.1.1", "10.0.0.5"],
                    "packet_count": 1500,
                },
            }
        }


class DashboardOverviewResponse(BaseModel):
    """Comprehensive dashboard overview"""

    system_stats: SystemStatsResponse = Field(..., description="System health metrics")
    threat_summary: ThreatSummaryResponse = Field(
        ..., description="Threat detection summary"
    )
    traffic_summary: TrafficSummaryResponse = Field(
        ..., description="Network traffic summary"
    )
    recent_alerts: List[Alert] = Field(..., description="Recent security alerts")
    last_updated: datetime = Field(..., description="Time dashboard was last updated")

    class Config:
        json_schema_extra = {
            "example": {
                "system_stats": {
                    "cpu_usage": 45.2,
                    "memory_usage": 67.8,
                    "memory_total": 17179869184,
                    "memory_used": 11639193600,
                    "network_sent": 102457890,
                    "network_recv": 204857123,
                    "disk_usage": 32.1,
                    "threat_count": 42,
                    "firewall_actions": 128,
                    "uptime": 86400.5,
                    "timestamp": "2023-07-15T14:30:00Z",
                },
                "threat_summary": {
                    "time_range": "24h",
                    "total_threats": 42,
                    "threats_by_type": {
                        "Port Scan": 15,
                        "SQL Injection": 8,
                        "DDoS": 5,
                        "Malware": 10,
                        "Other": 4,
                    },
                    "top_source_ips": [
                        {
                            "ip": "192.168.1.100",
                            "count": 8,
                            "last_seen": "2023-07-15T14:25:00Z",
                            "country": "US",
                            "is_internal": True,
                        }
                    ],
                    "start_time": "2023-07-14T14:30:00Z",
                    "end_time": "2023-07-15T14:30:00Z",
                },
                "traffic_summary": {
                    "active_connections": 42,
                    "known_hosts": 15,
                    "threats_detected": 8,
                    "protocol_distribution": {
                        "tcp": {
                            "protocol": "tcp",
                            "count": 1200,
                            "bytes": 1024000,
                            "percentage": 65.2,
                        }
                    },
                    "inbound_bytes": 102457890,
                    "outbound_bytes": 204857123,
                    "timestamp": "2023-07-15T14:30:00Z",
                },
                "recent_alerts": [
                    {
                        "id": "alert-12345",
                        "timestamp": "2023-07-15T14:25:00Z",
                        "severity": "critical",
                        "type": "threat",
                        "title": "DDoS Attack Detected",
                        "description": "Large volume of SYN packets from multiple sources",
                        "source": "IDS",
                        "acknowledged": False,
                    }
                ],
                "last_updated": "2023-07-15T14:30:00Z",
            }
        }
