from sqlalchemy import Column, Integer, String, Enum, DateTime, ForeignKey
from sqlalchemy.sql import func
from app.database import Base
from enum import Enum as PyEnum


class AccessLevel(str, PyEnum):
    READ_ONLY = "read_only"
    OPERATOR = "operator"
    ADMIN = "admin"


class Access(Base):
    __tablename__ = "access_controls"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    resource_type = Column(String(50), nullable=False)
    resource_id = Column(Integer)
    access_level = Column(Enum(AccessLevel), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<Access {self.id} - User {self.user_id} to {self.resource_type}>"
