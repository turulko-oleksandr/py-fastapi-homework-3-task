from pydantic import BaseModel, EmailStr, Field, constr


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str | constr(min_length=8)


class UserRegistrationResponseSchema(BaseModel):
    email: str
    id: int


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str | constr(min_length=8)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    refresh_token: str


class MessageResponseSchema(BaseModel):
    message: str
