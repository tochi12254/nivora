from sqlalchemy import Column, String, JSON
# from sqlalchemy.dialects.postgresql import JSONB # Import JSONB for PostgreSQL
from sqlalchemy.ext.declarative import declarative_base

# Assuming 'Base' is defined in your project, e.g., in app.models.base
# If not, you might need to define it or import it appropriately.
# For this example, let's assume it's available from app.models.base
from .base import Base # Make sure this import path is correct for your project structure

class SystemSetting(Base):
    __tablename__ = "system_settings"

    key = Column(String, primary_key=True, index=True, unique=True)
    # Use JSONB if using PostgreSQL for better performance and features.
    # For SQLite or other DBs, JSON might be more appropriate or might fallback to TEXT.
    # Check your SQLAlchemy dialect documentation.
    # For this example, we'll try to use JSONB and fallback to JSON
    try:
        value = Column(JSON)
    except ImportError: # JSONB might not be available for all dialects (e.g. SQLite before certain versions)
        value = Column(JSON)

    # If you want to add created_at and updated_at manually:
    # from sqlalchemy import DateTime
    # from sqlalchemy.sql import func
    # created_at = Column(DateTime(timezone=True), server_default=func.now())
    # updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<SystemSetting(key='{self.key}', value='{self.value}')>"
