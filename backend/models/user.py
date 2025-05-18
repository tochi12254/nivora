from sqlalchemy import Column, Integer, String, Enum, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.database import Base
from enum import Enum as PyEnum


class UserRole(str, PyEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(Enum(UserRole), unique=True, nullable=False)
    description = Column(String(255), nullable=True)

    users = relationship("User", back_populates="role_relation")

    def __repr__(self):
        return f"<Role {self.id} - {self.name}>"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100))

    # Foreign key to Role table
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    role_relation = relationship("Role", back_populates="users")

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_login = Column(DateTime(timezone=True))

    def __repr__(self):
        return f"<User {self.id} - {self.username}>"
