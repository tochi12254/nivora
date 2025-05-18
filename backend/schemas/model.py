from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional
from enum import Enum


class ModelType(str, Enum):
    ANOMALY = "anomaly"
    SIGNATURE = "signature"
    BEHAVIORAL = "behavioral"


class ModelStatus(str, Enum):
    TRAINING = "training"
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"


class ModelBase(BaseModel):
    name: str
    type: ModelType
    version: str
    description: Optional[str] = None
    parameters: dict


class ModelCreate(ModelBase):
    training_data_path: str


class ModelUpdate(BaseModel):
    status: Optional[ModelStatus] = None
    accuracy: Optional[float] = None
    last_trained: Optional[datetime] = None


class ModelInDB(ModelBase):
    id: int
    status: ModelStatus
    accuracy: Optional[float] = None
    created_at: datetime
    updated_at: datetime
    last_trained: Optional[datetime] = None

    class Config:
        orm_mode = True


class ModelResponse(ModelInDB):
    pass


class ModelPrediction(BaseModel):
    model_id: int
    input_data: dict
    prediction: dict
    confidence: float
    timestamp: datetime
