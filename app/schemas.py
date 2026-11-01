"""Pydantic request/response schemas: validate inputs at the API boundary."""
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints
from typing_extensions import Annotated

ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]
NotesText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=10000)]
JobStatus = Literal["New", "In Progress", "Completed", "Cancelled"]
ReportStatus = Literal["Draft", "Approved", "Rejected"]
TaskStatus = Literal["Pending", "Completed"]


class UserCreate(BaseModel):
    email: EmailStr
    # A long minimum helps passphrase use; the server never logs the password.
    password: str = Field(min_length=12, max_length=128)


class UserLogin(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class EmailVerificationRequest(BaseModel):
    token: str = Field(min_length=32, max_length=256)


class EmailRequest(BaseModel):
    email: EmailStr


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class CustomerCreate(BaseModel):
    name: ShortText
    phone: str | None = Field(default=None, max_length=40)
    email: EmailStr | None = None
    address: str | None = Field(default=None, max_length=300)


class CustomerUpdate(BaseModel):
    name: ShortText | None = None
    phone: str | None = Field(default=None, max_length=40)
    email: EmailStr | None = None
    address: str | None = Field(default=None, max_length=300)


class CustomerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    phone: str | None
    email: str | None
    address: str | None
    created_at: datetime


class JobCreate(BaseModel):
    customer_id: int = Field(gt=0)
    title: ShortText
    trade_type: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=80)]
    description: str | None = Field(default=None, max_length=4000)
    notes: str | None = Field(default=None, max_length=10000)
    status: JobStatus = "New"


class JobUpdate(BaseModel):
    title: ShortText | None = None
    trade_type: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=80)] | None = None
    description: str | None = Field(default=None, max_length=4000)
    notes: str | None = Field(default=None, max_length=10000)
    status: JobStatus | None = None


class JobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    customer_id: int
    title: str
    trade_type: str
    description: str | None
    notes: str | None
    status: str
    created_at: datetime


class ReportDraftRequest(BaseModel):
    notes: NotesText


class ReportEdit(BaseModel):
    # JSON-encoded object string keeps the storage format simple for the MVP.
    generated_content: NotesText


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    job_id: int
    original_notes: str
    generated_content: str
    status: str
    created_at: datetime
    updated_at: datetime


class TaskCreate(BaseModel):
    title: ShortText
    due_at: datetime | None = None


class TaskUpdate(BaseModel):
    title: ShortText | None = None
    due_at: datetime | None = None
    status: TaskStatus | None = None


class TaskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    job_id: int
    title: str
    due_at: datetime | None
    status: str
    created_at: datetime
