import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.core.config import get_settings
from app.core.security import password_problems


class SignupIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=200)
    email: EmailStr
    password: str
    confirm_password: str

    @field_validator("full_name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = " ".join(v.split())
        if len(v) < 2:
            raise ValueError("Enter your full name")
        return v

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return v.strip().lower()

    @model_validator(mode="after")
    def _check(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        probs = password_problems(self.password, self.email, self.full_name, get_settings().password_min_length)
        if probs:
            raise ValueError("Password needs: " + ", ".join(probs))
        return self


class LoginIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)

    @field_validator("email")
    @classmethod
    def _email(cls, v: str) -> str:
        return v.strip().lower()


class MeOut(BaseModel):
    id: str
    email: str
    full_name: str
    status: str
    roles: list[str]
    permissions: list[str]


class ApproveIn(BaseModel):
    role: str = "employee"


class RejectIn(BaseModel):
    reason: str = Field("", max_length=500)


class SetRolesIn(BaseModel):
    roles: list[str] = Field(min_length=1, max_length=5)


class AdminUserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    email: str
    full_name: str
    status: str
    roles: list[str]
    created_at: datetime
    approved_at: datetime | None
    last_login_at: datetime | None
