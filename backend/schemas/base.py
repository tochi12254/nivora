from enum import Enum
from pydantic import BaseModel, validator, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address


class SeverityLevel(str, Enum):
    """Standardized severity levels for security events"""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Protocol(str, Enum):
    """Network protocol types"""

    ANY = "any"
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    SSH = "ssh"
    SMTP = "smtp"
    FTP = "ftp"
    RDP = "rdp"


class Direction(str, Enum):
    """Traffic direction"""

    INBOUND = "inbound"
    OUTBOUND = "outbound"
    INTERNAL = "internal"
    ANY = "any"


class IPAddress(BaseModel):
    """IP address with geolocation and threat context"""

    address: str
    is_internal: bool
    geo_info: Optional[Dict[str, str]] = None
    threat_score: Optional[float] = None
    last_seen: Optional[datetime] = None
    tags: Optional[List[str]] = None

    @validator("address")
    def validate_ip_address(cls, v):
        try:
            IPv4Address(v)
        except ValueError:
            try:
                IPv6Address(v)
            except ValueError:
                raise ValueError("Invalid IP address format")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "address": "192.168.1.100",
                "is_internal": True,
                "geo_info": {"country": "US", "city": "New York", "asn": "AS15169"},
                "threat_score": 0.85,
                "last_seen": "2023-07-15T14:30:00Z",
                "tags": ["scanner", "repeater"],
            }
        }


class PortRange(BaseModel):
    """Network port range specification"""

    start: int = Field(..., ge=1, le=65535)
    end: int = Field(..., ge=1, le=65535)

    @validator("end")
    def validate_range(cls, v, values):
        if "start" in values and v < values["start"]:
            raise ValueError("End port must be >= start port")
        return v

    class Config:
        json_schema_extra = {"example": {"start": 1000, "end": 2000}}


class TimeRange(BaseModel):
    """Time range filter for queries"""

    start: datetime
    end: datetime

    @validator("end")
    def validate_timerange(cls, v, values):
        if "start" in values and v < values["start"]:
            raise ValueError("End time must be after start time")
        return v

    class Config:
        json_schema_extra = {
            "example": {"start": "2023-07-15T00:00:00Z", "end": "2023-07-15T23:59:59Z"}
        }


class PaginationParams(BaseModel):
    """Standard pagination parameters"""

    page: int = Field(1, ge=1)
    per_page: int = Field(100, ge=1, le=1000)


class PaginatedResponse(BaseModel):
    """Base model for paginated responses"""

    total: int
    page: int
    per_page: int
    items: List[Any]

    class Config:
        json_schema_extra = {
            "example": {"total": 150, "page": 1, "per_page": 50, "items": []}
        }


class GeoInfo(BaseModel):
    """Geolocation information"""

    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[str] = None
    org: Optional[str] = None

    class Config:
        json_schema_extra = {
            "example": {
                "country": "United States",
                "country_code": "US",
                "city": "New York",
                "latitude": 40.7128,
                "longitude": -74.0060,
                "asn": "AS15169",
                "org": "Google LLC",
            }
        }


class ThreatIntel(BaseModel):
    """Threat intelligence data"""

    score: float = Field(..., ge=0, le=1)
    sources: List[str]
    last_updated: datetime
    tags: List[str] = []
    confidence: float = Field(..., ge=0, le=1)

    class Config:
        json_schema_extra = {
            "example": {
                "score": 0.92,
                "sources": ["AlienVault", "AbuseIPDB"],
                "last_updated": "2023-07-15T12:00:00Z",
                "tags": ["botnet", "scanner"],
                "confidence": 0.85,
            }
        }


class BaseAlert(BaseModel):
    """Base alert model for security events"""

    id: str
    timestamp: datetime
    severity: SeverityLevel
    source: str
    description: str
    is_active: bool = True
    metadata: Dict[str, Any] = {}

    class Config:
        json_schema_extra = {
            "example": {
                "id": "alert-12345",
                "timestamp": "2023-07-15T14:30:00Z",
                "severity": "high",
                "source": "IDS",
                "description": "Multiple SQL injection attempts detected",
                "is_active": True,
                "metadata": {"source_ip": "192.168.1.100", "count": 5},
            }
        }
