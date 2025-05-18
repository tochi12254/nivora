from pydantic import BaseModel, Field, IPvAnyAddress
from datetime import datetime
from typing import Optional
from enum import Enum


class FirewallAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class FirewallDirection(str, Enum):
    IN = "in"
    OUT = "out"
    BOTH = "both"


class FirewallProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class FirewallRuleBase(BaseModel):
    name: str
    action: FirewallAction
    direction: FirewallDirection
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = Field(None, ge=1, le=65535)
    destination_port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: FirewallProtocol = FirewallProtocol.ANY
    is_active: bool = True


class FirewallRuleCreate(FirewallRuleBase):
    pass


class FirewallRuleUpdate(BaseModel):
    name: Optional[str] = None
    action: Optional[FirewallAction] = None
    is_active: Optional[bool] = None


class FirewallRuleInDB(FirewallRuleBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True


class FirewallRuleResponse(FirewallRuleInDB):
    pass


class FirewallLog(BaseModel):
    timestamp: datetime
    rule_id: int
    action: FirewallAction
    source_ip: str
    destination_ip: str
    protocol: str
    matched_rule: str

    class Config:
        from_attributes = True


class FirewallStats(BaseModel):
    total_rules: int
    active_rules: int
    blocked_last_24h: int
    allowed_last_24h: int
