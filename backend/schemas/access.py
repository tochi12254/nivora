from pydantic import BaseModel, Field, EmailStr
from typing import Optional
from datetime import datetime
from enum import Enum

class AccessLevel(str, Enum):
    READ_ONLY = "read_only"
    OPERATOR = "operator"
    ADMIN = "admin"

class AccessBase(BaseModel):
    user_id: int
    resource_type: str
    resource_id: Optional[int] = None
    access_level: AccessLevel

class AccessCreate(AccessBase):
    pass

class AccessUpdate(BaseModel):
    access_level: Optional[AccessLevel] = None

class AccessInDB(AccessBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

class AccessResponse(AccessInDB):
    pass