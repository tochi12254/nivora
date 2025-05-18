from pydantic import BaseModel, Field, IPvAnyAddress
from datetime import datetime
from typing import Optional, List
from enum import Enum


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"


class ConnectionStatus(str, Enum):
    ESTABLISHED = "established"
    CLOSED = "closed"
    TIMEOUT = "timeout"


class NetworkTrafficBase(BaseModel):
    source_ip: IPvAnyAddress
    destination_ip: IPvAnyAddress
    source_port: int = Field(..., ge=1, le=65535)
    destination_port: int = Field(..., ge=1, le=65535)
    protocol: Protocol
    bytes_sent: int
    bytes_received: int
    start_time: datetime
    end_time: Optional[datetime] = None
    status: ConnectionStatus


class NetworkTrafficCreate(NetworkTrafficBase):
    pass


class NetworkTrafficInDB(NetworkTrafficBase):
    id: int
    created_at: datetime

    class Config:
        orm_mode = True


class NetworkTrafficResponse(NetworkTrafficInDB):
    pass


class NetworkScanRequest(BaseModel):
    target_ips: List[IPvAnyAddress]
    ports: List[int] = Field(..., min_items=1)
    protocol: Protocol = Protocol.TCP
    timeout: float = 1.0


class NetworkScanResult(BaseModel):
    ip: IPvAnyAddress
    port: int
    is_open: bool
    service: Optional[str] = None
    banner: Optional[str] = None
