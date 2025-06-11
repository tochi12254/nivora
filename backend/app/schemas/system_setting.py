from typing import Any, List
from pydantic import BaseModel, EmailStr # PositiveInt might require pydantic.types or be direct in v2

# Generic Setting Schemas
class SettingBase(BaseModel):
    key: str
    value: Any

class SettingCreate(SettingBase):
    pass

class SettingUpdate(BaseModel):
    value: Any

class Setting(SettingBase):
    class Config:
        from_attributes = True # Replaces orm_mode = True in Pydantic v2

# Specific Setting Schemas
class SystemName(BaseModel):
    value: str

class NotificationEmails(BaseModel):
    value: List[EmailStr]

class SessionTimeout(BaseModel):
    # For Pydantic v1, you might use:
    # from pydantic import conint
    # value: conint(gt=0)
    # For Pydantic v2, PositiveInt can be imported from pydantic.types or might be built-in
    # For simplicity here, using int. API endpoint logic should validate positivity.
    value: int # Should be a positive integer, representing minutes or seconds.
    
    # Example with PositiveInt if available and using Pydantic v2 style
    # from pydantic import PositiveInt
    # value: PositiveInt 

class SystemSettingsGroup(BaseModel):
    system_name: SystemName
    notification_emails: NotificationEmails
    session_timeout: SessionTimeout
