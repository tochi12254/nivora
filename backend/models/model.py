from sqlalchemy import Column, Integer, String, Enum, DateTime, Float, JSON
from sqlalchemy.sql import func
from app.database import Base
from enum import Enum as PyEnum


class ModelType(str, PyEnum):
    ANOMALY = "anomaly"
    SIGNATURE = "signature"
    BEHAVIORAL = "behavioral"


class ModelStatus(str, PyEnum):
    TRAINING = "training"
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"


class Model(Base):
    __tablename__ = "models"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    type = Column(Enum(ModelType), nullable=False)
    version = Column(String(50), nullable=False)
    description = Column(String(500))
    parameters = Column(JSON, nullable=False)
    status = Column(Enum(ModelStatus), default=ModelStatus.INACTIVE)
    accuracy = Column(Float)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    last_trained = Column(DateTime(timezone=True))

    def __repr__(self):
        return f"<Model {self.id} - {self.name} v{self.version}>"
