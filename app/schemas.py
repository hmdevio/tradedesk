
"""Pydantic request/response schemas: validate inputs at the API boundary."""

from datetime import datetime
from typing import Any, ClassVar, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    StringConstraints,
    model_validator,
)
from typing_extensions import Annotated


ShortText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=200,
    ),
]

# Lengths match the database columns so oversized input is rejected with 422
# instead of failing at the database (HTTP 500 on PostgreSQL).
CustomerName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=120,
    ),
]

JobTitle = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=160,
    ),
]

TradeType = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=80,
    ),
]

NotesText = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=10000,
    ),
]

JobStatus = Literal["New", "In Progress", "Completed", "Cancelled"]
ReportStatus = Literal["Draft", "Approved", "Rejected"]
TaskStatus = Literal["Pending", "Completed"]


class RejectNullFields(BaseModel):
    """Partial-update base: fields may be omitted but not explicitly null.

    Subclasses list required database columns in NON_NULLABLE. Sending
    {"name": null} would otherwise write NULL into a NOT NULL column.
    """

    NON_NULLABLE: ClassVar[tuple[str, ...]] = ()

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for field in cls.NON_NULLABLE:
                if field in data and data[field] is None:
                    raise ValueError(f"{field} cannot be null")
        return data


# Authentication schemas


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


class PasswordResetRequest(BaseModel):
    token: str = Field(min_length=32, max_length=256)
    # Same rules as registration.
    new_password: str = Field(min_length=12, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_seconds: int


class RegistrationResponse(BaseModel):
    message: str


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


# Customer schemas


class CustomerCreate(BaseModel):
    name: CustomerName
    phone: str | None = Field(default=None, max_length=40)
    email: EmailStr | None = None
    address: str | None = Field(default=None, max_length=300)


class CustomerUpdate(RejectNullFields):
    NON_NULLABLE: ClassVar[tuple[str, ...]] = ("name",)

    name: CustomerName | None = None
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


# Job schemas


class JobCreate(BaseModel):
    customer_id: int = Field(gt=0)
    title: JobTitle
    trade_type: TradeType
    description: str | None = Field(default=None, max_length=4000)
    notes: str | None = Field(default=None, max_length=10000)
    status: JobStatus = "New"


class JobUpdate(RejectNullFields):
    NON_NULLABLE: ClassVar[tuple[str, ...]] = (
        "title",
        "trade_type",
        "status",
    )

    title: JobTitle | None = None
    trade_type: TradeType | None = None
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


# Service report schemas


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


# Task schemas


class TaskCreate(BaseModel):
    title: ShortText
    due_at: datetime | None = None


class TaskUpdate(RejectNullFields):
    NON_NULLABLE: ClassVar[tuple[str, ...]] = ("title", "status")

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
