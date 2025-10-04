from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError
from passlib.context import CryptContext
from jose import jwt, JWTError
from config import settings, get_settings
from database import (
    UserModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
    UserGroupModel,
    UserGroupEnum,
)
from database import get_db
from schemas.accounts import (
    UserRegistrationRequestSchema,
    UserRegistrationResponseSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshRequestSchema,
    TokenRefreshResponseSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserActivationRequestSchema,
    MessageResponseSchema,
)

router = APIRouter(tags=["Accounts"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_token(data: dict, expires_delta: timedelta, secret_key: str, algorithm: str) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret_key, algorithm=algorithm)


def validate_password(password: str):
    import re
    if len(password) < 8:
        raise HTTPException(status_code=422, detail="Password must contain at least 8 characters.")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=422, detail="Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=422, detail="Password must contain at least one lower letter.")
    if not re.search(r"\d", password):
        raise HTTPException(status_code=422, detail="Password must contain at least one digit.")
    if not re.search(r"[@$!%*?#&]", password):
        raise HTTPException(
            status_code=422,
            detail="Password must contain at least one special character: @, $, !, %, *, ?, #, &."
        )


@router.post("/register/", status_code=201)
async def register_user(
    payload: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: settings = Depends(get_settings)
):
    validate_password(payload.password)

    stmt = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {payload.email} already exists."
        )

    stmt_group = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    result_group = await db.execute(stmt_group)
    user_group = result_group.scalars().first()

    if not user_group:
        raise HTTPException(status_code=500, detail="Default user group not found.")

    hashed_password = hash_password(payload.password)
    new_user = UserModel(
        email=payload.email,
        _hashed_password=hashed_password,
        is_active=False,
        group_id=user_group.id
    )
    db.add(new_user)

    try:
        await db.commit()
        await db.refresh(new_user)
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")

    token_value = create_token(
        {"user_id": new_user.id},
        timedelta(minutes=30),
        settings.SECRET_KEY_ACCESS,
        settings.JWT_SIGNING_ALGORITHM
    )
    activation_token = ActivationTokenModel(
        user_id=new_user.id,
        token=token_value,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=30)
    )
    db.add(activation_token)
    await db.commit()

    return {"email": new_user.email, "id": new_user.id}


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(
    payload: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    stmt_token = select(ActivationTokenModel).where(ActivationTokenModel.user_id == user.id)
    result_token = await db.execute(stmt_token)
    token = result_token.scalars().first()

    if not token or token.token != payload.token:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    token_expires = token.expires_at
    if token_expires.tzinfo is None:
        token_expires = token_expires.replace(tzinfo=timezone.utc)

    if token_expires < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login_user(
    payload: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: settings = Depends(get_settings)
):
    stmt = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not verify_password(payload.password, user._hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    access_token = create_token(
        {"user_id": user.id},
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        settings.SECRET_KEY_ACCESS,
        settings.JWT_SIGNING_ALGORITHM
    )
    refresh_token_value = create_token(
        {"user_id": user.id},
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        settings.SECRET_KEY_REFRESH,
        settings.JWT_SIGNING_ALGORITHM
    )

    refresh_token = RefreshTokenModel(
        user_id=user.id,
        token=refresh_token_value,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    db.add(refresh_token)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return {"access_token": access_token, "refresh_token": refresh_token_value}


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    payload: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: settings = Depends(get_settings)
):
    try:
        decoded = jwt.decode(
            payload.refresh_token,
            settings.SECRET_KEY_REFRESH,
            algorithms=[settings.JWT_SIGNING_ALGORITHM]
        )
        user_id = decoded.get("user_id")
    except JWTError:
        raise HTTPException(status_code=400, detail="Token has expired.")

    stmt_token = select(RefreshTokenModel).where(RefreshTokenModel.token == payload.refresh_token)
    result_token = await db.execute(stmt_token)
    token_record = result_token.scalars().first()

    if not token_record:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    stmt_user = select(UserModel).where(UserModel.id == user_id)
    result_user = await db.execute(stmt_user)
    user = result_user.scalars().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    new_access_token = create_token(
        {"user_id": user.id},
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        settings.SECRET_KEY_ACCESS,
        settings.JWT_SIGNING_ALGORITHM
    )

    return {"access_token": new_access_token, "refresh_token": payload.refresh_token}


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=200)
async def request_password_reset(
    payload: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
    settings: settings = Depends(get_settings)
):
    stmt = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user or not user.is_active:
        return {"message": "If you are registered, you will receive an email with instructions."}

    token_value = create_token(
        {"user_id": user.id},
        timedelta(minutes=15),
        settings.SECRET_KEY_ACCESS,
        settings.JWT_SIGNING_ALGORITHM
    )
    reset_token = PasswordResetTokenModel(
        user_id=user.id,
        token=token_value,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=15)
    )
    db.add(reset_token)
    await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def complete_password_reset(
    payload: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(UserModel).where(UserModel.email == payload.email)
    result = await db.execute(stmt)
    user = result.scalars().first()

    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    stmt_token = select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    result_token = await db.execute(stmt_token)
    token_record = result_token.scalars().first()

    if not token_record or token_record.token != payload.token:
        if token_record:
            await db.delete(token_record)
            await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    token_expires = token_record.expires_at
    if token_expires.tzinfo is None:
        token_expires = token_expires.replace(tzinfo=timezone.utc)

    if token_expires < datetime.now(timezone.utc):
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    user._hashed_password = hash_password(payload.password)
    await db.delete(token_record)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while resetting the password.")

    return {"message": "Password reset successfully."}
