"""SQLAlchemy models. Ownership columns are used by authorization checks."""
from datetime import datetime, timezone
from sqlalchemy import ( Boolean, DateTime, ForeignKey, Integer, String, Text, Index, text, )
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base



def utc_now() -> datetime:
    """Use timezone-aware UTC timestamps for stored records."""
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    email_verified: Mapped[bool] = mapped_column(Boolean, default=True, server_default=text("1"), nullable=False)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    customers: Mapped[list["Customer"]] = relationship(back_populates="owner", cascade="all, delete-orphan")
    jobs: Mapped[list["Job"]] = relationship(back_populates="owner", cascade="all, delete-orphan")



class AuthSession(Base):
    """Server-side record for one revocable bearer-token session."""

    __tablename__ = "auth_sessions"
    __table_args__ = (Index("ix_auth_sessions_user_expiry", "user_id", "expires_at"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class EmailVerificationToken(Base):
    """Hashed, expiring, single-use email verification token."""
    __tablename__ = "email_verification_tokens"
    __table_args__ = (Index("ix_email_verification_tokens_user_expiry", "user_id", "expires_at"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Customer(Base):
    __tablename__ = "customers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    phone: Mapped[str | None] = mapped_column(String(40), nullable=True)
    email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    address: Mapped[str | None] = mapped_column(String(300), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    owner: Mapped["User"] = relationship(back_populates="customers")
    jobs: Mapped[list["Job"]] = relationship(
        back_populates="customer",
        cascade="all, delete-orphan",
    )


def normalize_email(email: str | None) -> str | None:
    """Normalize an email address before saving or comparing it."""
    if email:
        return email.strip().lower() or None
    return None


class Job(Base):
    __tablename__ = "jobs"

    __table_args__ = (
        Index(
            "uq_jobs_customer_title_normalized",
            "customer_id",
            text("lower(trim(title))"),
            unique=True,
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    customer_id: Mapped[int] = mapped_column(
        ForeignKey("customers.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    title: Mapped[str] = mapped_column(String(160), nullable=False)
    trade_type: Mapped[str] = mapped_column(String(80), nullable=False)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[str] = mapped_column(
        String(30),
        default="New",
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    owner: Mapped[User] = relationship(back_populates="jobs")
    customer: Mapped[Customer] = relationship(back_populates="jobs")

    reports: Mapped[list["ServiceReport"]] = relationship(
        back_populates="job",
        cascade="all, delete-orphan",
    )

    tasks: Mapped[list["Task"]] = relationship(
        back_populates="job",
        cascade="all, delete-orphan",
    )


class ServiceReport(Base):
    __tablename__ = "service_reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), index=True, nullable=False)
    original_notes: Mapped[str] = mapped_column(Text, nullable=False)
    generated_content: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="Draft", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
    job: Mapped[Job] = relationship(back_populates="reports")


class Task(Base):
    __tablename__ = "tasks"

    __table_args__ = (
        Index(
            "uq_tasks_job_title_normalized",
            "job_id",
            text("lower(trim(title))"),
            unique=True,
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    job_id: Mapped[int] = mapped_column(
        ForeignKey("jobs.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    title: Mapped[str] = mapped_column(String(200), nullable=False)

    due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        default="Pending",
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    job: Mapped[Job] = relationship(back_populates="tasks")
