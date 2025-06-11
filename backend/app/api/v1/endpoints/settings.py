from typing import List, Any

from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import EmailStr # PositiveInt might require pydantic.types or be direct in v2

from .... import crud

from ....schemas import system_setting 

from ....database import get_db
from ....models.user import User # For current_user dependency if needed for auth
from ....core.security import get_current_active_user # For auth

router = APIRouter()

# --- System Name ---
@router.get("/system_name", response_model=system_setting.SystemName)
async def read_system_name(db: AsyncSession = Depends(get_db)):
    """
    Retrieve the system name.
    Returns a default name if not set.
    """
    setting = await crud.crud_system_setting.get_setting(db, key="system_name")
    default_name = "CyberWatch Tower" # Default system name
    
    current_value = default_name
    if setting:
        # Ensure the value from DB is a string, otherwise use default
        current_value = str(setting.value) if isinstance(setting.value, (str, int, float)) else default_name

    return system_setting.SystemName(value=current_value)

@router.post("/system_name", response_model=system_setting.SystemName, dependencies=[Depends(get_current_active_user)])
async def update_system_name(
    system_name_in: system_setting.SystemName, 
    db: AsyncSession = Depends(get_db)
):
    """
    Update the system name. (Requires authentication)
    """
    if not system_name_in.value or not system_name_in.value.strip():
        raise HTTPException(status_code=400, detail="System name cannot be empty.")
    
    updated_setting = await crud.crud_system_setting.upsert_setting(
        db, key="system_name", value=system_name_in.value
    )
    # Ensure the returned value is correctly typed for the response model
    return system_setting.SystemName(value=str(updated_setting.value))

# --- Notification Emails ---
@router.get("/notification_emails", response_model=system_setting.NotificationEmails)
async def read_notification_emails(db: AsyncSession = Depends(get_db)):
    """
    Retrieve the list of notification email recipients.
    Returns an empty list if not set or if the stored value is not a list.
    """
    setting = await crud.crud_system_setting.get_setting(db, key="notification_emails")
    default_emails: List[EmailStr] = []
    
    current_value = default_emails
    if setting and isinstance(setting.value, list):
        try:
            # Validate each email in the list
            valid_emails = [EmailStr(email) for email in setting.value if isinstance(email, str)]
            current_value = valid_emails
        except ValueError:
            # If any email is invalid, or if data is malformed, return default.
            # Or, you could log an error and return default.
            pass # current_value remains default_emails
            
    return system_setting.NotificationEmails(value=current_value)

@router.post("/notification_emails", response_model=system_setting.NotificationEmails, dependencies=[Depends(get_current_active_user)])
async def update_notification_emails(
    emails_in: system_setting.NotificationEmails, 
    db: AsyncSession = Depends(get_db)
):
    """
    Update the list of notification email recipients. (Requires authentication)
    Pydantic's NotificationEmails schema (value: List[EmailStr]) handles validation.
    """
    # The emails_in.value is already validated as List[EmailStr] by Pydantic
    # We need to store it as a list of strings for JSON serialization.
    string_emails = [str(email) for email in emails_in.value]
    
    updated_setting = await crud.crud_system_setting.upsert_setting(
        db, key="notification_emails", value=string_emails
    )
    # Re-cast to EmailStr for the response model, though it should be fine as strings too if schema expects EmailStr
    # The value from DB will be List[str], Pydantic will validate it for response_model
    return system_setting.NotificationEmails(value=[EmailStr(email) for email in updated_setting.value])


# --- Session Timeout ---
@router.get("/session_timeout", response_model=system_setting.SessionTimeout)
async def read_session_timeout(db: AsyncSession = Depends(get_db)):
    """
    Retrieve the session timeout duration in minutes.
    Returns a default value if not set or if the stored value is not a positive integer.
    """
    setting = await crud.crud_system_setting.get_setting(db, key="session_timeout")
    default_timeout_minutes = 30  # Default to 30 minutes
    
    current_value = default_timeout_minutes
    if setting and isinstance(setting.value, int) and setting.value > 0:
        current_value = setting.value
        
    return system_setting.SessionTimeout(value=current_value)

@router.post("/session_timeout", response_model=system_setting.SessionTimeout, dependencies=[Depends(get_current_active_user)])
async def update_session_timeout(
    timeout_in: system_setting.SessionTimeout,
    db: AsyncSession = Depends(get_db)
):
    """
    Update the session timeout duration in minutes. (Requires authentication)
    Value must be a positive integer.
    """
    if not isinstance(timeout_in.value, int) or timeout_in.value <= 0:
        raise HTTPException(status_code=400, detail="Session timeout must be a positive integer minutes.")
    
    updated_setting = await crud.crud_system_setting.upsert_setting(
        db, key="session_timeout", value=timeout_in.value
    )
    return system_setting.SessionTimeout(value=int(updated_setting.value))

# --- Grouped Settings (Example endpoint) ---
@router.get("/all", response_model=system_setting.SystemSettingsGroup, dependencies=[Depends(get_current_active_user)])
async def read_all_system_settings(db: AsyncSession = Depends(get_db)):
    """
    Retrieve all system settings grouped together. (Requires authentication)
    """
    system_name_data = await read_system_name(db)
    notification_emails_data = await read_notification_emails(db)
    session_timeout_data = await read_session_timeout(db)

    return system_setting.SystemSettingsGroup(
        system_name=system_name_data,
        notification_emails=notification_emails_data,
        session_timeout=session_timeout_data,
    )
