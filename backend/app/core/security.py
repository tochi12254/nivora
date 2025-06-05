# backend/app/core/security.py
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, AsyncGenerator
import os
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from ..database import get_db

# UserModel will be referred to as User as it's imported like that
from ..models.user import User

# UserInDB is not directly used in the functions being modified to return UserModel, so keeping it for now
from ..schemas.user import UserInDB

# TokenData will be imported from schemas.token by auth.py, remove local one if not used, or update.
# For now, the prompt doesn't explicitly say to remove it from here, but get_current_user will be changed to use scope.
# The prompt for get_current_user implies TokenData from schemas.token.py will be used.
# Let's remove the local definition to avoid conflict and assume it's resolved via auth.py's imports.
# from pydantic import BaseModel # BaseModel might still be needed if other Pydantic models are here. It's a common import.
from ..schemas.token import TokenData  # Explicitly import TokenData to be clear

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# The prompt mentions the tokenUrl for OAuth2PasswordBearer should be "auth/login/token"
# relative to the /api/v1 prefix. The current one is "api/auth/token".
# This will be: /api/v1/auth/login/token.
# If main app has /api/v1 prefix, then "auth/login/token" is correct.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login/token")

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Removed local TokenData class


def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),  # db session is already provided
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        scope: Optional[str] = payload.get("scope")  # Get scope for 2FA temp token
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username, scope=scope)  # Pass scope
    except JWTError:
        raise credentials_exception

    # Use the db session directly provided by Depends(get_db)
    # Corrected the execute call
    result = await db.execute(select(User).where(User.username == token_data.username))
    user = result.scalars().first()
    if user is None:
        raise credentials_exception
    return user  # Return UserModel (which is User here)


async def get_current_active_user(
    current_user: User = Depends(get_current_user),  # Expect User (UserModel)
):
    if not current_user.is_active:  # is_active is on User model
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def authenticate_user(
    username: str, password: str, db_session: AsyncSession  # Add db_session parameter
) -> Optional[User]:  # Return User model
    # Use the passed db_session directly
    result = await db_session.execute(select(User).where(User.username == username))
    user = result.scalars().first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user  # Return the User model
