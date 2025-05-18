from typing import Any
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, DateTime
from sqlalchemy.sql import func
from datetime import datetime

Base = declarative_base()


class BaseModel:
    """Base model class that provides common columns and functionality"""

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True), onupdate=func.now(), server_default=func.now()
    )

    def __repr__(self) -> str:
        """Generate a string representation of the model"""
        return f"<{self.__class__.__name__} {self.id}>"

    def to_dict(self) -> dict[str, Any]:
        """Convert model instance to dictionary"""
        return {
            column.name: getattr(self, column.name)
            for column in self.__table__.columns  # type: ignore
            if column.name not in ["created_at", "updated_at"]
        }

    def update(self, **kwargs) -> None:
        """Update model attributes"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    @classmethod
    def get_columns(cls) -> list[str]:
        """Get list of column names for the model"""
        return [column.name for column in cls.__table__.columns]  # type: ignore


# Create the actual Base class that combines declarative_base with our BaseModel
Model = declarative_base(cls=BaseModel)


# Helper function for timestamp columns
def timestamp() -> Column:
    return Column(DateTime, default=datetime.utcnow, nullable=False)


# Common mixins for specialized functionality
class SoftDeleteMixin:
    """Mixin for soft delete functionality"""

    is_deleted = Column(Integer, default=0, nullable=False)
    deleted_at = Column(DateTime(timezone=True))

    def soft_delete(self) -> None:
        """Mark the record as deleted without actually removing it"""
        self.is_deleted = 1
        self.deleted_at = func.now()


class AuditMixin:
    """Mixin for audit tracking"""

    created_by = Column(Integer, nullable=True)
    updated_by = Column(Integer, nullable=True)

    def set_creator(self, user_id: int) -> None:
        """Set the user who created the record"""
        self.created_by = user_id

    def set_updater(self, user_id: int) -> None:
        """Set the user who last updated the record"""
        self.updated_by = user_id
