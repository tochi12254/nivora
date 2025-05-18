from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional
from enum import Enum


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    full_name: Optional[str] = None
    role: UserRole = UserRole.VIEWER


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    password: Optional[str] = Field(None, min_length=8)


class UserInDB(UserBase):
    id: int
    is_active: bool = True
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserResponse(UserInDB):
    pass


class UserLogin(BaseModel):
    username: str
    password: str


class RoleCreate(BaseModel):
    name: UserRole
    description: Optional[str] = None


class RoleResponse(BaseModel):
    id: int
    name: UserRole
    description: Optional[str] = None

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    username: Optional[str] = None
    scopes: list[str] = []
