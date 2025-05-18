from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List, Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import os

from app.database import get_db
from models.user import User, Role
from schemas.user import (
    UserCreate,
    UserResponse,
    UserUpdate,
    RoleCreate,
    RoleResponse,
    Token,
    TokenData,
)
from app.utils.security import TokenUtils, SecurityConfig
from app.utils.monitoring import track_function_metrics

router = APIRouter(tags=["Users"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/users/token")


# Authentication
@router.post("/token", response_model=Token)
@track_function_metrics("user_login")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=SecurityConfig.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = TokenUtils.create_access_token(
        data={"sub": user.username, "roles": [r.name for r in user.roles]},
        expires_delta=access_token_expires,
    )

    return {"access_token": access_token, "token_type": "bearer"}


def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if not user or not pwd_context.verify(password, user.hashed_password):
        return False
    return user


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = TokenUtils.verify_token(token)
        if payload is None:
            raise credentials_exception

        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception

        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception

    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# User Management
@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)


@track_function_metrics("user_create")
async def create_user(
    user: UserCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = pwd_context.hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password,
        is_active=True,
        created_at=datetime.utcnow(),
        created_by=current_user.username,
    )

    # Assign roles
    for role_name in user.roles:
        role = db.query(Role).filter(Role.name == role_name).first()
        if role:
            db_user.roles.append(role)

    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@router.get("/users/me", response_model=UserResponse)
@track_function_metrics("user_get_me")
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@router.get("/users", response_model=List[UserResponse])

@track_function_metrics("user_list")
async def read_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    users = db.query(User).offset(skip).limit(limit).all()
    return users


@router.get("/users/{user_id}", response_model=UserResponse)

@track_function_metrics("user_get")
async def read_user(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@router.put("/users/{user_id}", response_model=UserResponse)

@track_function_metrics("user_update")
async def update_user(
    user_id: int,
    user: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if user.username and user.username != db_user.username:
        existing_user = db.query(User).filter(User.username == user.username).first()
        if existing_user:
            raise HTTPException(status_code=400, detail="Username already in use")
        db_user.username = user.username

    if user.email:
        db_user.email = user.email

    if user.full_name:
        db_user.full_name = user.full_name

    if user.password:
        db_user.hashed_password = pwd_context.hash(user.password)

    if user.is_active is not None:
        db_user.is_active = user.is_active

    if user.roles:
        db_user.roles = []
        for role_name in user.roles:
            role = db.query(Role).filter(Role.name == role_name).first()
            if role:
                db_user.roles.append(role)

    db_user.updated_at = datetime.utcnow()
    db_user.updated_by = current_user.username

    db.commit()
    db.refresh(db_user)
    return db_user


@router.delete("/users/{user_id}")

@track_function_metrics("user_delete")
async def delete_user(
    user_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if db_user.username == current_user.username:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    db.delete(db_user)
    db.commit()
    return {"status": "success", "message": "User deleted"}


# Role Management
@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)

@track_function_metrics("role_create")
async def create_role(
    role: RoleCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    db_role = db.query(Role).filter(Role.name == role.name).first()
    if db_role:
        raise HTTPException(status_code=400, detail="Role already exists")

    db_role = Role(
        name=role.name,
        description=role.description,
        created_at=datetime.utcnow(),
        created_by=current_user.username,
    )

    db.add(db_role)
    db.commit()
    db.refresh(db_role)
    return db_role


@router.get("/roles", response_model=List[RoleResponse])
# @role_required(["admin", "security_analyst"])
@track_function_metrics("role_list")
async def read_roles(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    roles = db.query(Role).offset(skip).limit(limit).all()
    return roles
