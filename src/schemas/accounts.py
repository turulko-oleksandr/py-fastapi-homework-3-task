from pydantic import BaseModel, EmailStr, Field, constr


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str


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
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    refresh_token: str


class MessageResponseSchema(BaseModel):
    message: str
