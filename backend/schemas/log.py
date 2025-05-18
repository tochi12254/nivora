from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
from enum import Enum
from sqlalchemy import Column, Integer, String, DateTime, Text
from app.database import Base

class LogType(str, Enum):
    SECURITY = "security"
    SYSTEM = "system"
    NETWORK = "network"
    AUDIT = "audit"


class LogLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class LogBase(BaseModel):
    type: LogType
    level: LogLevel
    message: str
    source: str
    details: Optional[dict] = None


class LogCreate(LogBase):
    pass


class LogInDB(LogBase):
    id: int
    timestamp: datetime
    user_id: Optional[int] = None

    class Config:
        from_attributes = True


class LogResponse(LogInDB):
    pass


class LogFilter(BaseModel):
    type: Optional[LogType] = None
    level: Optional[LogLevel] = None
    source: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None


class NetworkLog(Base):
    __tablename__ = "network_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True)
    threat_type = Column(String(100), index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45), index=True)
    protocol = Column(String(10))
    length = Column(Integer)
    raw_data = Column(Text)
