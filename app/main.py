
"""TradeDesk FastAPI application.

Security-oriented notes:
- All business records are filtered by the authenticated owner.
- The API returns generic authentication failures.
- AI-generated text remains a draft until an explicit approval action.
- New accounts must verify their email before signing in.
- Verification tokens are high-entropy, single-use, and stored as hashes.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import secrets
from pathlib import Path
from uuid import uuid4

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pwdlib import PasswordHash
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import Base, engine, get_db
from app.dependencies import get_current_session, get_current_user
from app.email_delivery import (
    send_existing_account_email,
    send_password_reset_email,
    send_verification_email,
)
from app.models import (
    AuthSession,
    Customer,
    EmailVerificationToken,
    Job,
    PasswordResetToken,
    ServiceReport,
    Task,
    User,
    normalize_email,
)
from app.rate_limit import enforce_rate_limit, verify_redis_connection
from app.reporting import (
    ReportContentError,
    ReportContext,
    create_pdf,
    make_report_draft,
    validate_report_content,
)
from app.schemas import (
    CustomerCreate,
    CustomerOut,
    CustomerUpdate,
    EmailRequest,
    EmailVerificationRequest,
    JobCreate,
    JobOut,
    JobUpdate,
    PasswordChange,
    PasswordResetRequest,
    RegistrationResponse,
    ReportDraftRequest,
    ReportEdit,
    ReportOut,
    TaskCreate,
    TaskOut,
    TaskUpdate,
    TokenResponse,
    UserCreate,
    UserLogin,
)
from app.security import create_access_token, hash_password, verify_password


logger = logging.getLogger(__name__)

settings = get_settings()

ENVIRONMENT = settings.environment.strip().lower()
IS_PRODUCTION = ENVIRONMENT == "production"


if IS_PRODUCTION:
    if len(settings.secret_key) < 32:
        raise RuntimeError(
            "SECRET_KEY must contain at least 32 characters in production"
        )


dummy_hasher = PasswordHash.recommended()

# Compute once at startup; do not spend extra Argon2 work for every unknown email.
DUMMY_PASSWORD_HASH = dummy_hasher.hash("not-a-real-user-password")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize SQLite development schema; PostgreSQL uses Alembic."""
    if IS_PRODUCTION:
        verify_redis_connection()

    elif engine.dialect.name == "sqlite":
        # SQLite is used for local development and automated tests.
        Base.metadata.create_all(bind=engine)

    # PostgreSQL schema changes must be applied through Alembic.
    yield


app = FastAPI(
    title="TradeDesk API",
    description="AI-assisted job documentation for independent tradespeople.",
    version="0.1.0",
    lifespan=lifespan,
    # Keep docs available for local development. Disable in production.
    docs_url=None if IS_PRODUCTION else "/docs",
    redoc_url=None if IS_PRODUCTION else "/redoc",
)


# Empty allowlist by default. Configure exact trusted origins only when needed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.parsed_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# Browser security headers (audit finding S2).
# The frontend uses no inline scripts or styles, so a strict CSP applies.
# Interactive API docs (development only) load assets from a CDN and are
# excluded from the CSP.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data: blob:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)
DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


# Validation errors (audit findings S10 and U9).
# FastAPI's default 422 body copies each rejected value back to the client,
# including passwords, and the interface could only show "Request failed".
# This handler drops the submitted values and returns one readable sentence
# in "detail" plus a field list in "errors".
FIELD_LABELS = {
    "email": "Email",
    "password": "Password",
    "current_password": "Current password",
    "new_password": "New password",
    "token": "Link",
    "name": "Name",
    "phone": "Phone",
    "address": "Address",
    "customer_id": "Customer",
    "title": "Title",
    "trade_type": "Trade type",
    "description": "Description",
    "notes": "Notes",
    "status": "Status",
    "due_at": "Due date",
    "generated_content": "Report content",
}


def _readable_validation_error(error: dict) -> dict[str, str]:
    location = [str(part) for part in error.get("loc", ()) if part != "body"]
    field = location[-1] if location else ""
    message = str(error.get("msg", "Invalid value"))
    message = message.removeprefix("Value error, ")
    label = FIELD_LABELS.get(field, field.replace("_", " ").capitalize())
    return {
        "field": field,
        "message": f"{label}: {message}" if label else message,
    }


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    errors = [_readable_validation_error(error) for error in exc.errors()]
    detail = "; ".join(error["message"] for error in errors[:3])
    return JSONResponse(
        status_code=422,
        content={
            "detail": detail or "Please check your input.",
            "errors": errors,
        },
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    headers = response.headers
    headers.setdefault("X-Content-Type-Options", "nosniff")
    headers.setdefault("X-Frame-Options", "DENY")
    headers.setdefault("Referrer-Policy", "no-referrer")
    headers.setdefault(
        "Permissions-Policy",
        "camera=(), microphone=(), geolocation=()",
    )
    if not request.url.path.startswith(DOCS_PATHS):
        headers.setdefault(
            "Content-Security-Policy", CONTENT_SECURITY_POLICY
        )
    # API responses carry customer data; keep them out of shared caches.
    if not request.url.path.startswith("/static") and request.url.path != "/":
        headers.setdefault("Cache-Control", "no-store")
    if IS_PRODUCTION:
        headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )
    return response


# Serve the static interface. Keep API authorization checks in backend routes.
STATIC_DIR = Path(__file__).parent / "static"

app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR),
    name="static",
)


@app.get("/", include_in_schema=False)
def home():
    """Serve the dashboard shell; the frontend calls the protected API."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    """Basic liveness check; do not expose secrets or infrastructure details."""
    return {"status": "ok"}


# Authentication and session management


def issue_session(db: Session, user: User) -> TokenResponse:
    """Persist a revocable session before returning its signed bearer token."""
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.access_token_minutes)

    session = AuthSession(
        id=str(uuid4()),
        user_id=user.id,
        expires_at=expires_at,
        created_at=now,
    )

    db.add(session)

    # Remove expired records opportunistically.
    # Revoked records remain until their expiration.
    # synchronize_session=False: expired rows are never in use by this
    # request, and in-memory evaluation fails on SQLite's naive datetimes.
    db.execute(
        delete(AuthSession)
        .where(AuthSession.expires_at <= now)
        .execution_options(synchronize_session=False)
    )

    db.commit()

    token = create_access_token(
        user.id,
        session.id,
        expires_at,
    )

    return TokenResponse(
        access_token=token,
        expires_in_seconds=settings.access_token_minutes * 60,
    )


def create_verification_token(db: Session, user: User) -> None:
    """Rotate outstanding tokens and store only a digest of the new token."""
    now = datetime.now(timezone.utc)

    # Invalidate outstanding verification tokens for this user.
    db.query(EmailVerificationToken).filter(
        EmailVerificationToken.user_id == user.id,
        EmailVerificationToken.used_at.is_(None),
    ).update(
        {EmailVerificationToken.used_at: now},
        synchronize_session=False,
    )

    # Generate a high-entropy, URL-safe token.
    raw_token = secrets.token_urlsafe(48)

    # Store only the SHA-256 digest, never the original token.
    token_digest = hashlib.sha256(
        raw_token.encode("utf-8")
    ).hexdigest()

    verification_token = EmailVerificationToken(
        user_id=user.id,
        token_hash=token_digest,
        expires_at=now + timedelta(
            minutes=settings.email_verification_minutes
        ),
        created_at=now,
    )

    db.add(verification_token)
    db.commit()

    # The raw token is used only for email delivery.
    # It is never returned in the API response or stored in the database.
    send_verification_email(user.email, raw_token)


@app.post(
    "/auth/register",
    response_model=RegistrationResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(
    payload: UserCreate,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> RegistrationResponse:
    """Create an unverified account and send an email verification link."""
    enforce_rate_limit(
        request,
        "register",
        limit=3,
        window_seconds=3600,
    )

    email = normalize_email(str(payload.email))

    existing = db.scalar(
        select(User).where(
            func.lower(func.trim(User.email)) == email
        )
    )

    if existing is not None:
        # Audit findings S4, S7 and N1 (2026-11-18 re-audit).
        # Registering an email that already has an account never changes
        # that account. Before, the newest registration replaced the
        # password, so someone could register after the real owner and
        # take over the account once the owner clicked the new link (N1),
        # and a verified email returned 409, which revealed that the
        # account existed (S7).
        # Now every existing account gets the same 201 response, any
        # pending verification links are voided, and the address is
        # emailed a password setup link. Whoever controls the inbox
        # chooses the password; the reset also marks the email verified.
        hash_password(payload.password)  # Similar work to a new account.
        _void_verification_tokens(db, existing)
        token = _create_password_reset_token(db, existing)
        background_tasks.add_task(
            _deliver_existing_account_notice,
            existing.id,
            existing.email,
            token,
        )
        return RegistrationResponse(message=REGISTRATION_MESSAGE)

    user = User(
        email=email,
        password_hash=hash_password(payload.password),
        email_verified=False,
    )

    db.add(user)

    try:
        db.commit()
        db.refresh(user)

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="Unable to create account with those details",
        ) from None

    return _send_registration_verification(db, user)


def _send_registration_verification(
    db: Session,
    user: User,
) -> RegistrationResponse:
    """Issue a verification token and email it for a saved account."""
    try:
        create_verification_token(db, user)

    except Exception as exc:
        # Roll back any unfinished transaction.
        # The account itself was committed before verification delivery.
        db.rollback()

        # Log only the user ID and exception type.
        # Do not log email addresses, tokens, or exception messages.
        logger.error(
            "Registration verification delivery failed "
            "for user_id=%s error_type=%s",
            user.id,
            type(exc).__name__,
        )

        # The account remains saved but unverified.
        # The user can request another verification email.
        # Do not expose SMTP or infrastructure details.
        raise HTTPException(
            status_code=503,
            detail=(
                "Registration was saved, but verification email delivery "
                "is temporarily unavailable. Please try resending the email."
            ),
        ) from None

    return RegistrationResponse(message=REGISTRATION_MESSAGE)


# One response for new and existing emails, so registration does not reveal
# which addresses have accounts.
REGISTRATION_MESSAGE = (
    "Account created. Check your email to verify your address "
    "before signing in."
)


def _void_verification_tokens(db: Session, user: User) -> None:
    """Mark every outstanding verification link for the account as used."""
    db.execute(
        update(EmailVerificationToken)
        .where(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.used_at.is_(None),
        )
        .values(used_at=datetime.now(timezone.utc))
    )


def _deliver_existing_account_notice(
    user_id: int, email: str, token: str
) -> None:
    """Background delivery of the password setup link for an existing email."""
    try:
        send_existing_account_email(email, token)
    except Exception as exc:
        # Log only the user ID and exception type, never the email or token.
        logger.error(
            "Existing-account notice delivery failed "
            "for user_id=%s error_type=%s",
            user_id,
            type(exc).__name__,
        )


@app.post("/auth/verify-email")
def verify_email(
    payload: EmailVerificationRequest,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Consume one valid, unexpired verification token exactly once."""
    now = datetime.now(timezone.utc)

    digest = hashlib.sha256(
        payload.token.encode("utf-8")
    ).hexdigest()

    # Atomic conditional update:
    # Only an unused, unexpired token can be consumed.
    statement = (
        update(EmailVerificationToken)
        .where(
            EmailVerificationToken.token_hash == digest,
            EmailVerificationToken.used_at.is_(None),
            EmailVerificationToken.expires_at > now,
        )
        .values(used_at=now)
        .returning(EmailVerificationToken.user_id)
    )

    user_id = db.execute(statement).scalar_one_or_none()

    if user_id is None:
        db.rollback()

        raise HTTPException(
            status_code=400,
            detail="Verification link is invalid or expired",
        )

    user = db.get(User, user_id)

    if user is None:
        db.rollback()

        raise HTTPException(
            status_code=400,
            detail="Verification link is invalid or expired",
        )

    user.email_verified = True
    user.email_verified_at = now

    # Invalidate all other outstanding tokens for this account.
    db.execute(
        update(EmailVerificationToken)
        .where(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.used_at.is_(None),
        )
        .values(used_at=now)
    )

    db.commit()

    return {
        "message": "Email verified. You can now sign in."
    }


@app.post("/auth/resend-verification")
def resend_verification(
    payload: EmailRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Resend verification without revealing whether an account exists."""
    enforce_rate_limit(
        request,
        "email-verification",
        limit=3,
        window_seconds=3600,
    )

    email = normalize_email(str(payload.email))

    user = db.scalar(
        select(User).where(
            func.lower(func.trim(User.email)) == email
        )
    )

    if user is not None and not user.email_verified:
        try:
            create_verification_token(db, user)

        except Exception as exc:
            # Restore the database session after a failed operation.
            db.rollback()

            # Log only the user ID and exception type.
            # Do not log email addresses, tokens, or exception messages.
            logger.error(
                "Verification email resend failed "
                "for user_id=%s error_type=%s",
                user.id,
                type(exc).__name__,
            )

            # Preserve the same generic response for every account state.
            # Do not expose SMTP errors or account existence.

    return {
        "message": (
            "If the account requires verification, an email will be sent."
        )
    }


@app.post(
    "/auth/login",
    response_model=TokenResponse,
)
def login(
    payload: UserLogin,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Authenticate a verified user and issue a session-bound access token."""
    enforce_rate_limit(
        request,
        "login",
        limit=5,
        window_seconds=900,
    )

    email = normalize_email(str(payload.email))

    user = db.scalar(
        select(User).where(
            func.lower(func.trim(User.email)) == email
        )
    )

    # Verify a dummy hash for unknown emails to reduce obvious timing differences.
    if user is None:
        verify_password(
            payload.password,
            DUMMY_PASSWORD_HASH,
        )

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    if not verify_password(
        payload.password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password",
        )

    if not user.email_verified:
        raise HTTPException(
            status_code=403,
            detail="Verify your email address before signing in",
        )

    return issue_session(db, user)


@app.post(
    "/auth/logout",
    status_code=status.HTTP_204_NO_CONTENT,
)
def logout(
    auth_session: AuthSession = Depends(get_current_session),
    db: Session = Depends(get_db),
):
    """Revoke only the bearer token presented to this endpoint."""
    auth_session.revoked_at = datetime.now(timezone.utc)

    db.commit()

    return Response(
        status_code=status.HTTP_204_NO_CONTENT
    )


@app.post(
    "/auth/password",
    status_code=status.HTTP_204_NO_CONTENT,
)
def change_password(
    payload: PasswordChange,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Change the password and revoke all active sessions for the account."""
    if not verify_password(
        payload.current_password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=400,
            detail="Current password is incorrect",
        )

    now = datetime.now(timezone.utc)

    user.password_hash = hash_password(
        payload.new_password
    )

    db.query(AuthSession).filter(
        AuthSession.user_id == user.id,
        AuthSession.revoked_at.is_(None),
    ).update(
        {AuthSession.revoked_at: now},
        synchronize_session=False,
    )

    db.commit()

    return Response(
        status_code=status.HTTP_204_NO_CONTENT
    )


@app.post(
    "/auth/refresh",
    response_model=TokenResponse,
)
def refresh_session(
    auth_session: AuthSession = Depends(get_current_session),
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Exchange a live session for a new one and revoke the old token.

    Lets the interface keep an active user signed in (audit finding U3)
    without long-lived tokens. Only a valid, unexpired session can renew.
    """
    user = db.get(User, auth_session.user_id)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    auth_session.revoked_at = datetime.now(timezone.utc)
    return issue_session(db, user)


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _create_password_reset_token(db: Session, user: User) -> str:
    """Rotate outstanding reset tokens and store only the new digest."""
    now = datetime.now(timezone.utc)

    db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        )
        .values(used_at=now)
    )

    raw_token = secrets.token_urlsafe(48)
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=_hash_token(raw_token),
            expires_at=now + timedelta(
                minutes=settings.password_reset_minutes
            ),
            created_at=now,
        )
    )
    db.commit()
    return raw_token


def _deliver_password_reset(user_id: int, email: str, token: str) -> None:
    """Background delivery so response timing doesn't reveal accounts."""
    try:
        send_password_reset_email(email, token)
    except Exception as exc:
        # Log only the user ID and exception type, never the email or token.
        logger.error(
            "Password reset delivery failed for user_id=%s error_type=%s",
            user_id,
            type(exc).__name__,
        )


@app.post("/auth/forgot-password")
def forgot_password(
    payload: EmailRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Email a reset link without revealing whether an account exists."""
    enforce_rate_limit(
        request,
        "password-reset",
        limit=3,
        window_seconds=3600,
    )

    email = normalize_email(str(payload.email))
    user = db.scalar(
        select(User).where(func.lower(func.trim(User.email)) == email)
    )

    if user is not None:
        token = _create_password_reset_token(db, user)
        background_tasks.add_task(
            _deliver_password_reset, user.id, user.email, token
        )

    return {
        "message": (
            "If an account exists for that email, a reset link will be sent."
        )
    }


@app.post("/auth/reset-password")
def reset_password(
    payload: PasswordResetRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Consume a valid reset token once, set the password, end all sessions."""
    enforce_rate_limit(
        request,
        "password-reset-confirm",
        limit=10,
        window_seconds=900,
    )

    now = datetime.now(timezone.utc)

    user_id = db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.token_hash == _hash_token(payload.token),
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .values(used_at=now)
        .returning(PasswordResetToken.user_id)
    ).scalar_one_or_none()

    user = db.get(User, user_id) if user_id is not None else None
    if user is None:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail="Reset link is invalid or expired",
        )

    user.password_hash = hash_password(payload.new_password)

    # Opening the emailed link proves control of the address.
    if not user.email_verified:
        user.email_verified = True
        user.email_verified_at = now

    for token_model in (PasswordResetToken, EmailVerificationToken):
        db.execute(
            update(token_model)
            .where(
                token_model.user_id == user.id,
                token_model.used_at.is_(None),
            )
            .values(used_at=now)
        )

    db.execute(
        update(AuthSession)
        .where(
            AuthSession.user_id == user.id,
            AuthSession.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )

    db.commit()

    return {"message": "Password updated. You can now sign in."}


# Customer email uniqueness helper


def is_customer_email_unique_violation(
    exc: IntegrityError,
) -> bool:
    """Identify violations of the normalized customer email index."""
    original = exc.orig

    # PostgreSQL drivers expose the violated constraint name.
    diagnostic = getattr(original, "diag", None)
    constraint_name = getattr(
        diagnostic,
        "constraint_name",
        None,
    )

    if constraint_name == "uq_customers_user_email_normalized":
        return True

    # SQLite includes the expression index name in its error message.
    return (
        "uq_customers_user_email_normalized"
        in str(original)
    )


# Ownership validation helpers


def owned_customer(
    db: Session,
    customer_id: int,
    user_id: int,
) -> Customer:
    """Return a customer only when it belongs to the authenticated user."""
    customer = db.scalar(
        select(Customer).where(
            Customer.id == customer_id,
            Customer.user_id == user_id,
        )
    )

    if customer is None:
        raise HTTPException(
            status_code=404,
            detail="Customer not found",
        )

    return customer


def owned_job(
    db: Session,
    job_id: int,
    user_id: int,
) -> Job:
    """Return a job only when it belongs to the authenticated user."""
    job = db.scalar(
        select(Job).where(
            Job.id == job_id,
            Job.user_id == user_id,
        )
    )

    if job is None:
        raise HTTPException(
            status_code=404,
            detail="Job not found",
        )

    return job


def owned_report(
    db: Session,
    report_id: int,
    user_id: int,
) -> ServiceReport:
    """Return a report only when its associated job belongs to the user."""
    report = db.scalar(
        select(ServiceReport)
        .join(Job)
        .where(
            ServiceReport.id == report_id,
            Job.user_id == user_id,
        )
    )

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="Report not found",
        )

    return report


def owned_task(
    db: Session,
    task_id: int,
    user_id: int,
) -> Task:
    """Return a task only when its associated job belongs to the user."""
    task = db.scalar(
        select(Task)
        .join(Job)
        .where(
            Task.id == task_id,
            Job.user_id == user_id,
        )
    )

    if task is None:
        raise HTTPException(
            status_code=404,
            detail="Task not found",
        )

    return task


# Customer management


@app.get(
    "/customers",
    response_model=list[CustomerOut],
)
def list_customers(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return list(
        db.scalars(
            select(Customer)
            .where(Customer.user_id == user.id)
            .order_by(Customer.id.desc())
        )
    )


@app.post(
    "/customers",
    response_model=CustomerOut,
    status_code=201,
)
def create_customer(
    payload: CustomerCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Create a customer while enforcing per-account email uniqueness."""
    email = normalize_email(payload.email)

    # Application-level duplicate check for a clear response.
    if email is not None:
        existing = db.scalar(
            select(Customer).where(
                Customer.user_id == user.id,
                func.lower(func.trim(Customer.email)) == email,
            )
        )

        if existing is not None:
            raise HTTPException(
                status_code=409,
                detail=(
                    "A customer with this email already exists "
                    "for this account."
                ),
            )

    customer = Customer(
        user_id=user.id,
        **payload.model_dump(exclude={"email"}),
        email=email,
    )

    db.add(customer)

    try:
        db.commit()

    except IntegrityError as exc:
        db.rollback()

        if is_customer_email_unique_violation(exc):
            raise HTTPException(
                status_code=409,
                detail=(
                    "A customer with this email already exists "
                    "for this account."
                ),
            ) from None

        # Do not misrepresent unrelated database errors as duplicates.
        raise

    db.refresh(customer)

    return customer


@app.get(
    "/customers/{customer_id}",
    response_model=CustomerOut,
)
def get_customer(
    customer_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return owned_customer(
        db,
        customer_id,
        user.id,
    )


@app.patch(
    "/customers/{customer_id}",
    response_model=CustomerOut,
)
def update_customer(
    customer_id: int,
    payload: CustomerUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Update an owned customer while enforcing email uniqueness."""
    customer = owned_customer(
        db,
        customer_id,
        user.id,
    )

    updates = payload.model_dump(exclude_unset=True)

    if "email" in updates:
        normalized_email = normalize_email(
            updates["email"]
        )

        # Only check for duplicates when an actual email is supplied.
        # NULL and blank email addresses are permitted.
        if normalized_email is not None:
            duplicate = db.scalar(
                select(Customer).where(
                    Customer.user_id == user.id,
                    Customer.id != customer_id,
                    func.lower(func.trim(Customer.email))
                    == normalized_email,
                )
            )

            if duplicate is not None:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "A customer with this email already exists "
                        "for this account."
                    ),
                )

        updates["email"] = normalized_email

    for field, value in updates.items():
        setattr(customer, field, value)

    try:
        db.commit()

    except IntegrityError as exc:
        db.rollback()

        if is_customer_email_unique_violation(exc):
            raise HTTPException(
                status_code=409,
                detail=(
                    "A customer with this email already exists "
                    "for this account."
                ),
            ) from None

        # Preserve visibility of unrelated database integrity failures.
        raise

    db.refresh(customer)

    return customer


@app.delete(
    "/customers/{customer_id}",
    status_code=204,
)
def delete_customer(
    customer_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    customer = owned_customer(
        db,
        customer_id,
        user.id,
    )

    db.delete(customer)
    db.commit()

    return Response(status_code=204)


# Job management


@app.get(
    "/jobs",
    response_model=list[JobOut],
)
def list_jobs(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return list(
        db.scalars(
            select(Job)
            .where(Job.user_id == user.id)
            .order_by(
                func.lower(Job.title).asc(),
                Job.id.desc(),
            )
        )
    )


@app.post(
    "/jobs",
    response_model=JobOut,
    status_code=201,
)
def create_job(
    payload: JobCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Verify ownership of the customer before attaching a job.
    owned_customer(
        db,
        payload.customer_id,
        user.id,
    )

    normalized_title = payload.title.strip()

    if not normalized_title:
        raise HTTPException(
            status_code=400,
            detail="Job title cannot be empty.",
        )

    existing_job = db.query(Job).filter(
        Job.customer_id == payload.customer_id,
        func.lower(func.trim(Job.title))
        == normalized_title.lower(),
    ).first()

    if existing_job:
        raise HTTPException(
            status_code=409,
            detail="A job with this title already exists for this customer.",
        )

    job_data = payload.model_dump()
    job_data["title"] = normalized_title

    job = Job(
        user_id=user.id,
        **job_data,
    )

    try:
        db.add(job)
        db.commit()
        db.refresh(job)

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="A job with this title already exists for this customer.",
        ) from None

    return job


@app.get(
    "/jobs/{job_id}",
    response_model=JobOut,
)
def get_job(
    job_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return owned_job(
        db,
        job_id,
        user.id,
    )


@app.patch(
    "/jobs/{job_id}",
    response_model=JobOut,
)
def update_job(
    job_id: int,
    payload: JobUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    job = owned_job(
        db,
        job_id,
        user.id,
    )

    updates = payload.model_dump(exclude_unset=True)

    if "title" in updates:
        duplicate = db.scalar(
            select(Job).where(
                Job.customer_id == job.customer_id,
                Job.id != job.id,
                func.lower(func.trim(Job.title)) == updates["title"].lower(),
            )
        )
        if duplicate is not None:
            raise HTTPException(
                status_code=409,
                detail="A job with this title already exists for this customer.",
            )

    for field, value in updates.items():
        setattr(job, field, value)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="A job with this title already exists for this customer.",
        ) from None

    db.refresh(job)

    return job


@app.delete(
    "/jobs/{job_id}",
    status_code=204,
)
def delete_job(
    job_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    job = owned_job(
        db,
        job_id,
        user.id,
    )

    db.delete(job)
    db.commit()

    return Response(status_code=204)


# Service report management


@app.post(
    "/jobs/{job_id}/reports/draft",
    response_model=ReportOut,
    status_code=201,
)
def create_report_draft(
    job_id: int,
    payload: ReportDraftRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    job = owned_job(
        db,
        job_id,
        user.id,
    )

    # Local fallback makes the MVP testable without sending customer data
    # externally. Integrate a real AI provider only after reviewing its
    # privacy and data-retention terms.
    content = make_report_draft(payload.notes)

    report = ServiceReport(
        job_id=job.id,
        original_notes=payload.notes,
        generated_content=json.dumps(
            content,
            ensure_ascii=False,
        ),
        status="Draft",
    )

    db.add(report)
    db.commit()
    db.refresh(report)

    return report


@app.get(
    "/jobs/{job_id}/reports",
    response_model=list[ReportOut],
)
def list_reports(
    job_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List an owned job's reports, newest first (audit finding U2)."""
    owned_job(db, job_id, user.id)

    return list(
        db.scalars(
            select(ServiceReport)
            .join(Job)
            .where(
                ServiceReport.job_id == job_id,
                Job.user_id == user.id,
            )
            .order_by(ServiceReport.id.desc())
        )
    )


@app.get(
    "/reports/{report_id}",
    response_model=ReportOut,
)
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return owned_report(db, report_id, user.id)


@app.patch(
    "/reports/{report_id}",
    response_model=ReportOut,
)
def edit_report(
    report_id: int,
    payload: ReportEdit,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    report = owned_report(
        db,
        report_id,
        user.id,
    )

    if report.status != "Draft":
        raise HTTPException(
            status_code=409,
            detail="Only draft reports can be edited",
        )

    try:
        report.generated_content = validate_report_content(
            payload.generated_content
        )
    except ReportContentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None

    db.commit()
    db.refresh(report)

    return report


@app.post(
    "/reports/{report_id}/approve",
    response_model=ReportOut,
)
def approve_report(
    report_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    report = owned_report(
        db,
        report_id,
        user.id,
    )

    if report.status != "Draft":
        raise HTTPException(
            status_code=409,
            detail="Only draft reports can be approved",
        )

    report.status = "Approved"

    db.commit()
    db.refresh(report)

    return report


@app.get("/reports/{report_id}/pdf")
def export_report_pdf(
    report_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    report = owned_report(
        db,
        report_id,
        user.id,
    )

    if report.status != "Approved":
        raise HTTPException(
            status_code=409,
            detail="Only approved reports can be exported",
        )

    job = owned_job(
        db,
        report.job_id,
        user.id,
    )

    customer = owned_customer(db, job.customer_id, user.id)

    pdf_bytes = create_pdf(
        ReportContext(
            report_id=report.id,
            job_title=job.title,
            trade_type=job.trade_type,
            customer_name=customer.name,
            customer_address=customer.address,
            customer_phone=customer.phone,
            customer_email=customer.email,
            prepared_by=user.email,
            service_date=report.created_at,
            # Approval is the last permitted change to a report.
            approved_at=report.updated_at,
            content=report.generated_content,
            original_notes=report.original_notes,
        )
    )

    # Inline filename is static and content type is explicitly set.
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="tradedesk-report-{report.id}.pdf"'
            )
        },
    )


# Task management


@app.get(
    "/jobs/{job_id}/tasks",
    response_model=list[TaskOut],
)
def list_tasks(
    job_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    owned_job(
        db,
        job_id,
        user.id,
    )

    return list(
        db.scalars(
            select(Task)
            .join(Job)
            .where(
                Task.job_id == job_id,
                Job.user_id == user.id,
            )
            .order_by(Task.id.desc())
        )
    )


@app.post(
    "/jobs/{job_id}/tasks",
    response_model=TaskOut,
    status_code=201,
)
def create_task(
    job_id: int,
    payload: TaskCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Verify that the job belongs to the authenticated user.
    owned_job(
        db,
        job_id,
        user.id,
    )

    normalized_title = payload.title.strip()

    if not normalized_title:
        raise HTTPException(
            status_code=400,
            detail="Task title cannot be empty.",
        )

    existing_task = db.query(Task).filter(
        Task.job_id == job_id,
        func.lower(func.trim(Task.title))
        == normalized_title.lower(),
    ).first()

    if existing_task:
        raise HTTPException(
            status_code=409,
            detail="A task with this title already exists for this job.",
        )

    task_data = payload.model_dump()
    task_data["title"] = normalized_title

    task = Task(
        job_id=job_id,
        **task_data,
        status="Pending",
    )

    try:
        db.add(task)
        db.commit()
        db.refresh(task)

    except IntegrityError:
        db.rollback()

        raise HTTPException(
            status_code=409,
            detail="A task with this title already exists for this job.",
        ) from None

    return task


@app.patch(
    "/tasks/{task_id}",
    response_model=TaskOut,
)
def update_task(
    task_id: int,
    payload: TaskUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    task = owned_task(
        db,
        task_id,
        user.id,
    )

    updates = payload.model_dump(exclude_unset=True)

    if "title" in updates:
        duplicate = db.scalar(
            select(Task).where(
                Task.job_id == task.job_id,
                Task.id != task.id,
                func.lower(func.trim(Task.title)) == updates["title"].lower(),
            )
        )
        if duplicate is not None:
            raise HTTPException(
                status_code=409,
                detail="A task with this title already exists for this job.",
            )

    for field, value in updates.items():
        setattr(task, field, value)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="A task with this title already exists for this job.",
        ) from None

    db.refresh(task)

    return task


@app.delete(
    "/tasks/{task_id}",
    status_code=204,
)
def delete_task(
    task_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    task = owned_task(
        db,
        task_id,
        user.id,
    )

    db.delete(task)
    db.commit()

    return Response(status_code=204)
