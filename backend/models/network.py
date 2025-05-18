from sqlalchemy import Column, Integer, String, Enum, DateTime, BigInteger
from sqlalchemy.sql import func
from app.database import Base
from enum import Enum as PyEnum


class Protocol(str, PyEnum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"


class ConnectionStatus(str, PyEnum):
    ESTABLISHED = "established"
    CLOSED = "closed"
    TIMEOUT = "timeout"


class NetworkTraffic(Base):
    __tablename__ = "network_traffic"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(45), nullable=False)
    destination_ip = Column(String(45), nullable=False)
    source_port = Column(Integer, nullable=False)
    destination_port = Column(Integer, nullable=False)
    protocol = Column(Enum(Protocol), nullable=False)
    bytes_sent = Column(BigInteger, default=0)
    bytes_received = Column(BigInteger, default=0)
    start_time = Column(DateTime(timezone=True), nullable=False)
    end_time = Column(DateTime(timezone=True))
    status = Column(Enum(ConnectionStatus), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<NetworkTraffic {self.id} - {self.protocol} {self.source_ip}:{self.source_port}>"
