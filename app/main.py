
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
import base64
import hashlib
import json
import logging
import re
import secrets
from pathlib import Path
from uuid import uuid4

from typing import Annotated

from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
    Path as PathParam,
    Query,
    Request,
    Response,
    status,
)
from fastapi.security import HTTPAuthorizationCredentials
import jwt
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
from app.dependencies import (
    bearer_scheme,
    get_current_session,
    get_current_user,
)
from app.email_delivery import (
    send_existing_account_email,
    send_password_reset_email,
    send_verification_email,
)
from app.models import (
    AuthSession,
    BusinessProfile,
    Customer,
    EmailVerificationToken,
    Job,
    JobWorksheet,
    PasswordResetToken,
    ReportWorksheetSnapshot,
    ServiceReport,
    Task,
    User,
    WorksheetSketch,
    normalize_email,
)
from app.rate_limit import enforce_rate_limit, verify_redis_connection
from app.reporting import (
    PrintedBusiness,
    PrintedSketch,
    PrintedWorksheet,
    ReportContentError,
    ReportContext,
    create_pdf,
    make_report_draft,
    validate_report_content,
)
from app.worksheets import (
    MAX_LOGO_SIDE,
    MAX_SKETCHES_PER_JOB,
    TRADES,
    WorksheetError,
    printable_rows,
    process_sketch,
    public_templates,
    validate_notes,
    validate_values,
)
from app.schemas import (
    MAX_RECORD_ID,
    BusinessProfileIn,
    BusinessProfileOut,
    CustomerCreate,
    CustomerOut,
    CustomerUpdate,
    DeleteImpact,
    EmailRequest,
    LogoUpload,
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
    SketchCreate,
    SketchOut,
    TaskCreate,
    TaskOut,
    TaskUpdate,
    TokenResponse,
    UserCreate,
    UserLogin,
    WorksheetIn,
    WorksheetOut,
)

# Record IDs in URLs must fit a PostgreSQL INTEGER; anything else is a 422,
# not a database error.
RecordId = Annotated[int, PathParam(ge=1, le=MAX_RECORD_ID)]
from app.security import (
    ALGORITHM,
    create_access_token,
    hash_password,
    verify_password,
)


logger = logging.getLogger(__name__)

settings = get_settings()

ENVIRONMENT = settings.environment.strip().lower()
IS_PRODUCTION = ENVIRONMENT == "production"


# SECRET_KEY length and ENVIRONMENT are validated in app/config.py for every
# environment (audit finding S5), so a weak key cannot reach this point.


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

    if not IS_PRODUCTION and not settings.redis_url:
        # Make the development fallback visible (audit finding S5).
        logger.warning(
            "REDIS_URL is not set: rate limiting is disabled in %s mode",
            ENVIRONMENT,
        )

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


# JSON can carry a NUL character as the escape \u0000. PostgreSQL refuses NUL
# in text columns, so such a value would fail at the database with a 500.
# Reject it up front with a 422. The pattern counts preceding backslashes so a
# user who literally types "\u0000" (sent as \\u0000) is not affected.
NUL_ESCAPE = re.compile(rb"(?<!\\)(?:\\\\)*\\u0000")
BODY_METHODS = {"POST", "PUT", "PATCH"}


@app.middleware("http")
async def reject_nul_characters(request: Request, call_next):
    if request.method in BODY_METHODS and "json" in request.headers.get("content-type", ""):
        if NUL_ESCAPE.search(await request.body()):
            return JSONResponse(
                status_code=422,
                content={
                    "detail": "Text cannot contain NUL characters.",
                    "errors": [{"field": "body", "message": "Text cannot contain NUL characters."}],
                },
            )
    return await call_next(request)


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
# Display labels only, not credentials; the nosec marks tell Bandit (B105) so.
FIELD_LABELS = {
    "email": "Email",
    "password": "Password",  # nosec B105
    "current_password": "Current password",  # nosec B105
    "new_password": "New password",  # nosec B105
    "token": "Link",  # nosec B105
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
    "image": "Sketch file",
    "subject": "Subject",
    "trade": "Trade",
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


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> FileResponse:
    """Browsers ask for /favicon.ico on their own; serve the SVG icon (Sprint 1)."""
    return FileResponse(STATIC_DIR / "favicon.svg", media_type="image/svg+xml")


@app.get("/health")
def health() -> dict[str, str]:
    """Basic liveness check; do not expose secrets or infrastructure details."""
    return {"status": "ok"}


# Authentication and session management


def issue_session(
    db: Session,
    user: User,
    auth_time: datetime | None = None,
) -> TokenResponse:
    """Persist a revocable session before returning its signed bearer token.

    ``auth_time`` is when the password was last entered. A renewal passes the
    original value, and no session may outlive auth_time + SESSION_MAX_HOURS.
    """
    now = datetime.now(timezone.utc)
    auth_time = auth_time or now
    session_limit = auth_time + timedelta(hours=settings.session_max_hours)
    expires_at = min(
        now + timedelta(minutes=settings.access_token_minutes),
        session_limit,
    )
    if expires_at <= now:
        raise HTTPException(
            status_code=401,
            detail="Session time limit reached. Sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

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
        auth_time,
    )

    return TokenResponse(
        access_token=token,
        # The real remaining time: shorter than ACCESS_TOKEN_MINUTES near the
        # session limit, so the interface warns at the right moment.
        expires_in_seconds=max(int((expires_at - now).total_seconds()), 1),
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

    # Per-address limit (audit finding S9): stops one inbox from being
    # flooded with emails sent from many IP addresses.
    enforce_rate_limit(
        request,
        "register-email",
        limit=3,
        window_seconds=3600,
        subject=email,
    )

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
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, str]:
    """Verify an email with the emailed token AND the account's password.

    Audit remediation Phase 2b: before this, anyone who clicked a
    verification email verified the account under whatever password its
    creator chose, even if they had never registered. Asking for the
    password means only the person who registered can finish, and a
    stranger's click does nothing. A wrong password does not use up the link.
    """
    enforce_rate_limit(
        request,
        "email-verification-confirm",
        limit=10,
        window_seconds=900,
    )

    now = datetime.now(timezone.utc)
    invalid_link = HTTPException(
        status_code=400,
        detail="Verification link is invalid or expired",
    )

    digest = hashlib.sha256(
        payload.token.encode("utf-8")
    ).hexdigest()

    pending = db.scalar(
        select(EmailVerificationToken).where(
            EmailVerificationToken.token_hash == digest,
            EmailVerificationToken.used_at.is_(None),
            EmailVerificationToken.expires_at > now,
        )
    )
    user = db.get(User, pending.user_id) if pending is not None else None

    if user is None:
        raise invalid_link

    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=400,
            detail=(
                "That password doesn't match this account. Enter the "
                "password you chose when you created the account."
            ),
        )

    # Atomic conditional update:
    # Only an unused, unexpired token can be consumed, exactly once.
    consumed = db.execute(
        update(EmailVerificationToken)
        .where(
            EmailVerificationToken.id == pending.id,
            EmailVerificationToken.used_at.is_(None),
        )
        .values(used_at=now)
        .returning(EmailVerificationToken.user_id)
    ).scalar_one_or_none()

    if consumed is None:
        db.rollback()
        raise invalid_link

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

    # Per-account limit (audit finding S9): attempts from many IP addresses
    # against one account share this counter. Unknown emails are counted too,
    # so the response does not reveal which accounts exist.
    enforce_rate_limit(
        request,
        "login-account",
        limit=10,
        window_seconds=900,
        subject=email,
    )

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
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Change the password and revoke all active sessions for the account."""
    # Limits guessing the current password from a stolen session (S9).
    enforce_rate_limit(
        request,
        "password-change",
        limit=5,
        window_seconds=900,
        subject=f"user:{user.id}",
    )

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
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Exchange a live session for a new one and revoke the old token.

    Lets the interface keep an active user signed in (audit finding U3)
    without long-lived tokens. Only a valid, unexpired session can renew,
    and never past SESSION_MAX_HOURS after the original sign-in (Phase 2b).
    """
    user = db.get(User, auth_session.user_id)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    auth_time = _token_auth_time(credentials, auth_session)
    auth_session.revoked_at = datetime.now(timezone.utc)
    return issue_session(db, user, auth_time=auth_time)


def _token_auth_time(
    credentials: HTTPAuthorizationCredentials | None,
    auth_session: AuthSession,
) -> datetime:
    """Read the original sign-in time from an already validated token.

    Tokens issued before Phase 2b have no auth_time claim; their session's
    creation time is the closest safe value.
    """
    fallback = auth_session.created_at
    if fallback.tzinfo is None:  # SQLite returns naive UTC datetimes.
        fallback = fallback.replace(tzinfo=timezone.utc)
    if credentials is None:
        return fallback
    payload = jwt.decode(
        credentials.credentials,
        settings.secret_key,
        algorithms=[ALGORITHM],
    )
    claim = payload.get("auth_time")
    if isinstance(claim, int):
        return datetime.fromtimestamp(claim, tz=timezone.utc)
    return fallback


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

    # Per-address limit (S9): no inbox flooding from many IP addresses.
    enforce_rate_limit(
        request,
        "password-reset-email",
        limit=3,
        window_seconds=3600,
        subject=email,
    )

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


# List pagination (audit finding S13): every list returns at most PAGE_MAX
# rows per request. Use ?limit= and ?offset= to page through longer lists.
PAGE_DEFAULT = 100
PAGE_MAX = 200


# Customer management


@app.get(
    "/customers",
    response_model=list[CustomerOut],
)
def list_customers(
    limit: int = Query(PAGE_DEFAULT, ge=1, le=PAGE_MAX),
    offset: int = Query(0, ge=0, le=MAX_RECORD_ID),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return list(
        db.scalars(
            select(Customer)
            .where(Customer.user_id == user.id)
            .order_by(Customer.id.desc())
            .limit(limit)
            .offset(offset)
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
    customer_id: RecordId,
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
    customer_id: RecordId,
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
    customer_id: RecordId,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    customer = owned_customer(
        db,
        customer_id,
        user.id,
    )

    # Approved reports are the record a customer has received; deleting the
    # customer would delete them too (cascade). Sprint 1 / U5.
    if _delete_impact(db, customer_id=customer.id).approved_reports:
        raise HTTPException(
            status_code=409,
            detail=(
                "This customer has approved reports, so it can't be "
                "deleted. Mark their jobs Completed or Cancelled instead."
            ),
        )

    db.delete(customer)
    db.commit()

    return Response(status_code=204)


@app.get(
    "/customers/{customer_id}/impact",
    response_model=DeleteImpact,
)
def customer_delete_impact(
    customer_id: RecordId,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """What deleting this customer would also remove (for the confirmation)."""
    owned_customer(db, customer_id, user.id)
    return _delete_impact(db, customer_id=customer_id)


def _delete_impact(
    db: Session,
    *,
    customer_id: int | None = None,
    job_id: int | None = None,
) -> DeleteImpact:
    """Count the records a customer or job deletion cascades to."""
    if job_id is not None:
        job_ids = [job_id]
    else:
        job_ids = list(
            db.scalars(select(Job.id).where(Job.customer_id == customer_id))
        )
    if not job_ids:
        return DeleteImpact()

    def count(model, *conditions):
        return db.scalar(
            select(func.count()).select_from(model).where(*conditions)
        ) or 0

    return DeleteImpact(
        jobs=len(job_ids),
        reports=count(ServiceReport, ServiceReport.job_id.in_(job_ids)),
        approved_reports=count(
            ServiceReport,
            ServiceReport.job_id.in_(job_ids),
            ServiceReport.status == "Approved",
        ),
        tasks=count(Task, Task.job_id.in_(job_ids)),
        sketches=count(WorksheetSketch, WorksheetSketch.job_id.in_(job_ids)),
    )


# Job management


@app.get(
    "/jobs",
    response_model=list[JobOut],
)
def list_jobs(
    limit: int = Query(PAGE_DEFAULT, ge=1, le=PAGE_MAX),
    offset: int = Query(0, ge=0, le=MAX_RECORD_ID),
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
            .limit(limit)
            .offset(offset)
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
    job_id: RecordId,
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
    job_id: RecordId,
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
    job_id: RecordId,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    job = owned_job(
        db,
        job_id,
        user.id,
    )

    if _delete_impact(db, job_id=job.id).approved_reports:
        raise HTTPException(
            status_code=409,
            detail=(
                "This job has approved reports, so it can't be deleted. "
                "Mark it Completed or Cancelled instead."
            ),
        )

    db.delete(job)
    db.commit()

    return Response(status_code=204)


@app.get(
    "/jobs/{job_id}/impact",
    response_model=DeleteImpact,
)
def job_delete_impact(
    job_id: RecordId,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """What deleting this job would also remove (for the confirmation)."""
    owned_job(db, job_id, user.id)
    return _delete_impact(db, job_id=job_id)


# Service report management


@app.post(
    "/jobs/{job_id}/reports/draft",
    response_model=ReportOut,
    status_code=201,
)
def create_report_draft(
    job_id: RecordId,
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
    job_id: RecordId,
    limit: int = Query(PAGE_DEFAULT, ge=1, le=PAGE_MAX),
    offset: int = Query(0, ge=0, le=MAX_RECORD_ID),
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
            .limit(limit)
            .offset(offset)
        )
    )


@app.get(
    "/reports/{report_id}",
    response_model=ReportOut,
)
def get_report(
    report_id: RecordId,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    return owned_report(db, report_id, user.id)


@app.patch(
    "/reports/{report_id}",
    response_model=ReportOut,
)
def edit_report(
    report_id: RecordId,
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
    report_id: RecordId,
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

    # Freeze the job's worksheet and sketch list with the approval, so the
    # PDF the customer receives cannot change later (Phase 2c).
    db.add(
        ReportWorksheetSnapshot(
            report_id=report.id,
            content=json.dumps(
                {
                    **_worksheet_snapshot(db, report.job_id),
                    "business": _business_snapshot(db, user.id),
                },
                ensure_ascii=False,
            ),
        )
    )

    db.commit()
    db.refresh(report)

    return report


@app.get("/reports/{report_id}/pdf")
def export_report_pdf(
    report_id: RecordId,
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
    printed = _printed_worksheet(db, report)
    business = printed.get("business")

    pdf_bytes = create_pdf(
        ReportContext(
            report_id=report.id,
            job_title=job.title,
            trade_type=job.trade_type,
            customer_name=customer.name,
            customer_address=customer.address,
            customer_phone=customer.phone,
            customer_email=customer.email,
            # The business name from the approval snapshot; reports approved
            # before business profiles existed keep the account email.
            prepared_by=business.name if business else user.email,
            service_date=report.created_at,
            # Approval is the last permitted change to a report.
            approved_at=report.updated_at,
            content=report.generated_content,
            original_notes=report.original_notes,
            **printed,
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
    job_id: RecordId,
    limit: int = Query(PAGE_DEFAULT, ge=1, le=PAGE_MAX),
    offset: int = Query(0, ge=0, le=MAX_RECORD_ID),
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
            .limit(limit)
            .offset(offset)
        )
    )


@app.post(
    "/jobs/{job_id}/tasks",
    response_model=TaskOut,
    status_code=201,
)
def create_task(
    job_id: RecordId,
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
    task_id: RecordId,
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
    task_id: RecordId,
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


# Trade worksheets and sketches (Phase 2c)


def _worksheet_out(worksheet: JobWorksheet) -> WorksheetOut:
    try:
        values = json.loads(worksheet.data)
    except (TypeError, ValueError):
        values = {}
    return WorksheetOut(
        job_id=worksheet.job_id,
        trade=worksheet.trade,
        trade_label=TRADES.get(worksheet.trade, {}).get("label", worksheet.trade),
        values=values if isinstance(values, dict) else {},
        notes=worksheet.notes,
        updated_at=worksheet.updated_at,
    )


def _locked_sketch_ids(db: Session, job_id: int) -> set[int]:
    """Sketch IDs printed on an approved report of this job."""
    locked: set[int] = set()
    contents = db.scalars(
        select(ReportWorksheetSnapshot.content)
        .join(ServiceReport)
        .where(ServiceReport.job_id == job_id)
    )
    for content in contents:
        try:
            ids = json.loads(content).get("sketch_ids", [])
        except (TypeError, ValueError, AttributeError):
            continue
        locked.update(i for i in ids if isinstance(i, int))
    return locked


def _sketch_out(sketch: WorksheetSketch, locked: set[int]) -> SketchOut:
    out = SketchOut.model_validate(sketch)
    out.locked = sketch.id in locked
    return out


def _worksheet_snapshot(db: Session, job_id: int) -> dict:
    worksheet = db.scalar(
        select(JobWorksheet).where(JobWorksheet.job_id == job_id)
    )
    sketch_ids = list(
        db.scalars(
            select(WorksheetSketch.id)
            .where(WorksheetSketch.job_id == job_id)
            .order_by(WorksheetSketch.id)
        )
    )
    return {
        "trade": worksheet.trade if worksheet else None,
        "data": worksheet.data if worksheet else None,
        "notes": worksheet.notes if worksheet else None,
        "sketch_ids": sketch_ids,
    }


def _printed_worksheet(db: Session, report: ServiceReport) -> dict:
    """Worksheet and sketches for the PDF, from the approval snapshot.

    Reports approved before worksheets existed have no snapshot and print
    without a worksheet section.
    """
    snapshot_row = db.get(ReportWorksheetSnapshot, report.id)
    if snapshot_row is None:
        return {}
    try:
        snapshot = json.loads(snapshot_row.content)
    except (TypeError, ValueError):
        return {}

    printed: dict = {}
    business = _printed_business(snapshot.get("business"))
    if business is not None:
        printed["business"] = business
    if snapshot.get("trade"):
        label, rows = printable_rows(snapshot["trade"], snapshot.get("data") or "{}")
        notes = snapshot.get("notes")
        if rows or notes:
            printed["worksheet"] = PrintedWorksheet(label, rows, notes)

    ids = [i for i in snapshot.get("sketch_ids", []) if isinstance(i, int)]
    if ids:
        sketches = db.scalars(
            select(WorksheetSketch)
            .where(
                WorksheetSketch.id.in_(ids),
                WorksheetSketch.job_id == report.job_id,
            )
            .order_by(WorksheetSketch.id)
        )
        printed["sketches"] = [
            PrintedSketch(sketch.subject, sketch.image) for sketch in sketches
        ]
    return printed


@app.get("/worksheet-templates")
def worksheet_templates(
    user: User = Depends(get_current_user),
) -> list[dict]:
    """Field definitions for each trade's worksheet."""
    return public_templates()


@app.get(
    "/jobs/{job_id}/worksheet",
    response_model=WorksheetOut | None,
)
def get_worksheet(
    job_id: RecordId,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Return the job's worksheet, or null when none has been saved."""
    owned_job(db, job_id, user.id)
    worksheet = db.scalar(
        select(JobWorksheet).where(JobWorksheet.job_id == job_id)
    )
    return _worksheet_out(worksheet) if worksheet else None


@app.put(
    "/jobs/{job_id}/worksheet",
    response_model=WorksheetOut,
)
def save_worksheet(
    job_id: RecordId,
    payload: WorksheetIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Create or replace the job's worksheet after validating every value."""
    owned_job(db, job_id, user.id)
    try:
        values = validate_values(payload.trade, payload.values)
        notes = validate_notes(payload.notes)
    except WorksheetError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None

    worksheet = db.scalar(
        select(JobWorksheet).where(JobWorksheet.job_id == job_id)
    )
    if worksheet is None:
        worksheet = JobWorksheet(job_id=job_id, trade=payload.trade, data="{}")
        db.add(worksheet)
    worksheet.trade = payload.trade
    worksheet.data = json.dumps(values, ensure_ascii=False)
    worksheet.notes = notes

    try:
        db.commit()
    except IntegrityError:
        # Two saves raced to create the same job's worksheet.
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="The worksheet was changed at the same time. Try again.",
        ) from None
    db.refresh(worksheet)
    return _worksheet_out(worksheet)


@app.delete(
    "/jobs/{job_id}/worksheet",
    status_code=204,
)
def delete_worksheet(
    job_id: RecordId,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    owned_job(db, job_id, user.id)
    db.execute(
        delete(JobWorksheet)
        .where(JobWorksheet.job_id == job_id)
        .execution_options(synchronize_session=False)
    )
    db.commit()
    return Response(status_code=204)


@app.get(
    "/jobs/{job_id}/sketches",
    response_model=list[SketchOut],
)
def list_sketches(
    job_id: RecordId,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    owned_job(db, job_id, user.id)
    locked = _locked_sketch_ids(db, job_id)
    return [
        _sketch_out(sketch, locked)
        for sketch in db.scalars(
            select(WorksheetSketch)
            .where(WorksheetSketch.job_id == job_id)
            .order_by(WorksheetSketch.id)
        )
    ]


@app.post(
    "/jobs/{job_id}/sketches",
    response_model=SketchOut,
    status_code=201,
)
def upload_sketch(
    job_id: RecordId,
    payload: SketchCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Attach a sketch or plot image with a subject line to a job.

    The image is decoded, size-checked and re-encoded before storage; see
    app/worksheets.process_sketch.
    """
    # Image processing costs CPU; cap uploads per account.
    enforce_rate_limit(
        request,
        "sketch-upload",
        limit=30,
        window_seconds=3600,
        subject=f"user:{user.id}",
    )
    owned_job(db, job_id, user.id)

    count = db.scalar(
        select(func.count())
        .select_from(WorksheetSketch)
        .where(WorksheetSketch.job_id == job_id)
    )
    if count >= MAX_SKETCHES_PER_JOB:
        raise HTTPException(
            status_code=409,
            detail=f"A job can have at most {MAX_SKETCHES_PER_JOB} sketches.",
        )

    try:
        image = process_sketch(payload.image)
    except WorksheetError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None

    sketch = WorksheetSketch(
        job_id=job_id,
        subject=payload.subject,
        content_type=image.content_type,
        image=image.content,
        size_bytes=len(image.content),
        width=image.width,
        height=image.height,
        sha256=image.sha256,
    )
    db.add(sketch)
    db.commit()
    db.refresh(sketch)
    return _sketch_out(sketch, set())


def owned_sketch(db: Session, sketch_id: int, user_id: int) -> WorksheetSketch:
    """Return a sketch only when its job belongs to the user."""
    sketch = db.scalar(
        select(WorksheetSketch)
        .join(Job)
        .where(WorksheetSketch.id == sketch_id, Job.user_id == user_id)
    )
    if sketch is None:
        raise HTTPException(status_code=404, detail="Sketch not found")
    return sketch


@app.get("/sketches/{sketch_id}/image")
def sketch_image(
    sketch_id: RecordId,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Serve a stored sketch to its owner only."""
    sketch = owned_sketch(db, sketch_id, user.id)
    extension = "png" if sketch.content_type == "image/png" else "jpg"
    return Response(
        content=sketch.image,
        media_type=sketch.content_type,
        headers={
            "Content-Disposition": (
                f'inline; filename="sketch-{sketch.id}.{extension}"'
            ),
        },
    )


@app.delete(
    "/sketches/{sketch_id}",
    status_code=204,
)
def delete_sketch(
    sketch_id: RecordId,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    sketch = owned_sketch(db, sketch_id, user.id)
    if sketch.id in _locked_sketch_ids(db, sketch.job_id):
        raise HTTPException(
            status_code=409,
            detail=(
                "This sketch is part of an approved report and can't be "
                "deleted."
            ),
        )
    db.delete(sketch)
    db.commit()
    return Response(status_code=204)


# Business profile (Sprint 1)


def _profile_out(profile: BusinessProfile) -> BusinessProfileOut:
    return BusinessProfileOut(
        business_name=profile.business_name,
        phone=profile.phone,
        email=profile.email,
        address=profile.address,
        license_number=profile.license_number,
        has_logo=profile.logo is not None,
        updated_at=profile.updated_at,
    )


def _user_profile(db: Session, user_id: int) -> BusinessProfile | None:
    return db.scalar(
        select(BusinessProfile).where(BusinessProfile.user_id == user_id)
    )


def _business_snapshot(db: Session, user_id: int) -> dict | None:
    """Business details frozen into a report at approval (logo as base64)."""
    profile = _user_profile(db, user_id)
    if profile is None:
        return None
    return {
        "name": profile.business_name,
        "phone": profile.phone,
        "email": profile.email,
        "address": profile.address,
        "license_number": profile.license_number,
        "logo": (
            base64.b64encode(profile.logo).decode("ascii")
            if profile.logo is not None else None
        ),
    }


def _printed_business(data) -> PrintedBusiness | None:
    if not isinstance(data, dict) or not data.get("name"):
        return None
    logo = None
    if data.get("logo"):
        try:
            logo = base64.b64decode(data["logo"])
        except (ValueError, TypeError):
            logo = None
    return PrintedBusiness(
        name=str(data["name"]),
        phone=data.get("phone"),
        email=data.get("email"),
        address=data.get("address"),
        license_number=data.get("license_number"),
        logo=logo,
    )


@app.get("/profile", response_model=BusinessProfileOut | None)
def get_profile(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """The account's business profile, or null when none is set."""
    profile = _user_profile(db, user.id)
    return _profile_out(profile) if profile else None


@app.put("/profile", response_model=BusinessProfileOut)
def save_profile(
    payload: BusinessProfileIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Create or update the business profile (blank fields are cleared)."""
    profile = _user_profile(db, user.id)
    if profile is None:
        profile = BusinessProfile(user_id=user.id, business_name=payload.business_name)
        db.add(profile)
    profile.business_name = payload.business_name
    profile.phone = payload.phone or None
    profile.email = normalize_email(str(payload.email)) if payload.email else None
    profile.address = payload.address or None
    profile.license_number = payload.license_number or None
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=409,
            detail="The profile was changed at the same time. Try again.",
        ) from None
    db.refresh(profile)
    return _profile_out(profile)


@app.put("/profile/logo", response_model=BusinessProfileOut)
def upload_logo(
    payload: LogoUpload,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Set the logo: checked and re-encoded like sketches, max 600 px."""
    enforce_rate_limit(
        request,
        "logo-upload",
        limit=20,
        window_seconds=3600,
        subject=f"user:{user.id}",
    )
    profile = _user_profile(db, user.id)
    if profile is None:
        raise HTTPException(
            status_code=409,
            detail="Save your business name before adding a logo.",
        )
    try:
        image = process_sketch(payload.image, max_side=MAX_LOGO_SIDE)
    except WorksheetError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None
    profile.logo = image.content
    profile.logo_content_type = image.content_type
    db.commit()
    db.refresh(profile)
    return _profile_out(profile)


@app.get("/profile/logo")
def get_logo(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    profile = _user_profile(db, user.id)
    if profile is None or profile.logo is None:
        raise HTTPException(status_code=404, detail="No logo")
    return Response(
        content=profile.logo,
        media_type=profile.logo_content_type or "image/png",
        headers={"Content-Disposition": 'inline; filename="logo"'},
    )


@app.delete("/profile/logo", status_code=204)
def delete_logo(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    profile = _user_profile(db, user.id)
    if profile is not None:
        profile.logo = None
        profile.logo_content_type = None
        db.commit()
    return Response(status_code=204)
