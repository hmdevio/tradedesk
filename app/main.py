"""TradeDesk FastAPI application.

Security-oriented notes:
- All business records are filtered by the authenticated owner.
- The API returns generic authentication failures.
- AI-generated text remains a draft until an explicit approval action.
"""
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from pwdlib import PasswordHash

from app.config import get_settings
from app.database import Base, engine, get_db
from app.dependencies import get_current_user
from app.models import Customer, Job, ServiceReport, Task, User, normalize_email
from app.reporting import create_pdf, make_report_draft
from app.schemas import (
    CustomerCreate, CustomerOut, CustomerUpdate, JobCreate, JobOut, JobUpdate,
    ReportDraftRequest, ReportEdit, ReportOut, TaskCreate, TaskOut, TaskUpdate,
    TokenResponse, UserCreate, UserLogin,
)
from app.security import create_access_token, hash_password, verify_password
from app.rate_limit import enforce_rate_limit, verify_redis_connection

settings = get_settings()

if settings.environment == "production":
    if len(settings.secret_key) < 32:
        raise RuntimeError(
            "SECRET_KEY must contain at least 32 characters in production"
        )
dummy_hasher = PasswordHash.recommended()
# Compute once at startup; do not spend extra Argon2 work for every unknown email.
DUMMY_PASSWORD_HASH = dummy_hasher.hash("not-a-real-user-password")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables for the capstone starter. Use Alembic migrations in production."""
    if settings.environment == "production":
        verify_redis_connection()
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title="TradeDesk API",
    description="AI-assisted job documentation for independent tradespeople.",
    version="0.1.0",
    lifespan=lifespan,
    # Keep docs available for local capstone development. Disable/protect in production.
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url="/redoc" if settings.environment != "production" else None,
)

# Empty allowlist by default. Configure exact trusted origins only when needed.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.parsed_cors_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# Serve the static MVP interface. Keep all API authorization checks in backend routes.
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def home():
    """Serve the dashboard shell; the frontend calls the protected API."""
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    """Basic liveness check; do not expose secrets or infrastructure details."""
    return {"status": "ok"}


@app.post("/auth/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    enforce_rate_limit(request, "register", limit=3, window_seconds=3600)
    email = normalize_email(str(payload.email))
    existing = db.scalar(select(User).where(func.lower(func.trim(User.email)) == email))
    if existing:
        # Generic response avoids exposing account details through a separate lookup.
        raise HTTPException(status_code=409, detail="Unable to create account with those details")
    user = User(email=email, password_hash=hash_password(payload.password))
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Unable to create account with those details") from None
    token = create_access_token(user.id)
    return TokenResponse(access_token=token, expires_in_seconds=settings.access_token_minutes * 60)


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: UserLogin, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    enforce_rate_limit(request, "login", limit=5, window_seconds=900)
    email = normalize_email(str(payload.email))
    user = db.scalar(select(User).where(func.lower(func.trim(User.email)) == email))
    # Verify a dummy hash for unknown emails to reduce obvious timing differences.
    if user is None:
        verify_password(payload.password, DUMMY_PASSWORD_HASH)
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    return TokenResponse(
        access_token=create_access_token(user.id),
        expires_in_seconds=settings.access_token_minutes * 60,
    )


def owned_customer(db: Session, customer_id: int, user_id: int) -> Customer:
    customer = db.scalar(select(Customer).where(Customer.id == customer_id, Customer.user_id == user_id))
    if customer is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer


def owned_job(db: Session, job_id: int, user_id: int) -> Job:
    job = db.scalar(select(Job).where(Job.id == job_id, Job.user_id == user_id))
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


def owned_report(db: Session, report_id: int, user_id: int) -> ServiceReport:
    report = db.scalar(
        select(ServiceReport).join(Job).where(ServiceReport.id == report_id, Job.user_id == user_id)
    )
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


def owned_task(db: Session, task_id: int, user_id: int) -> Task:
    task = db.scalar(select(Task).join(Job).where(Task.id == task_id, Job.user_id == user_id))
    if task is None:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@app.get("/customers", response_model=list[CustomerOut])
def list_customers(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return list(db.scalars(select(Customer).where(Customer.user_id == user.id).order_by(Customer.id.desc())))


@app.post("/customers", response_model=CustomerOut, status_code=201)
def create_customer(payload: CustomerCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    email = normalize_email(payload.email)
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
                detail=f"A customer with email '{existing.email}' already exists for this account. No duplicate record was created.",
            )
    customer = Customer(user_id=user.id, **payload.model_dump(exclude={"email"}), email=email)
    db.add(customer)
    db.commit()
    db.refresh(customer)
    return customer


@app.get("/customers/{customer_id}", response_model=CustomerOut)
def get_customer(customer_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return owned_customer(db, customer_id, user.id)


@app.patch("/customers/{customer_id}", response_model=CustomerOut)
def update_customer(customer_id: int, payload: CustomerUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    customer = owned_customer(db, customer_id, user.id)
    updates = payload.model_dump(exclude_unset=True)
    if "email" in updates:
        normalized_email = normalize_email(updates["email"])
        duplicate = db.scalar(
            select(Customer).where(
                Customer.user_id == user.id,
                Customer.id != customer_id,
                func.lower(func.trim(Customer.email)) == normalized_email,
            )
        )
        if duplicate is not None:
            raise HTTPException(
                status_code=409,
                detail=f"A customer with email '{duplicate.email}' already exists for this account. No duplicate record was created.",
            )
        updates["email"] = normalized_email
    for field, value in updates.items():
        setattr(customer, field, value)
    db.commit()
    db.refresh(customer)
    return customer


@app.delete("/customers/{customer_id}", status_code=204)
def delete_customer(customer_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    customer = owned_customer(db, customer_id, user.id)
    db.delete(customer)
    db.commit()
    return Response(status_code=204)


@app.get("/jobs", response_model=list[JobOut])
def list_jobs(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    return list(
        db.scalars(
            select(Job)
            .where(Job.user_id == user.id)
            .order_by(
                func.lower(Job.title).asc(),
                Job.id.desc()
            )
        )
    )


@app.post("/jobs", response_model=JobOut, status_code=201)
def create_job(
    payload: JobCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Verify ownership of the customer before attaching a job.
    owned_customer(db, payload.customer_id, user.id)

    # Normalize the job title.
    normalized_title = payload.title.strip()

    if not normalized_title:
        raise HTTPException(
            status_code=400,
            detail="Job title cannot be empty.",
        )

    # Check for an existing job with the same normalized title
    # belonging to the same customer.
    existing_job = db.query(Job).filter(
        Job.customer_id == payload.customer_id,
        func.lower(func.trim(Job.title)) == normalized_title.lower(),
    ).first()

    if existing_job:
        raise HTTPException(
            status_code=409,
            detail="A job with this title already exists for this customer.",
        )

    # Create the job using the normalized title.
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
        )

    return job


@app.get("/jobs/{job_id}", response_model=JobOut)
def get_job(job_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return owned_job(db, job_id, user.id)


@app.patch("/jobs/{job_id}", response_model=JobOut)
def update_job(job_id: int, payload: JobUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    job = owned_job(db, job_id, user.id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(job, field, value)
    db.commit()
    db.refresh(job)
    return job


@app.delete("/jobs/{job_id}", status_code=204)
def delete_job(job_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    job = owned_job(db, job_id, user.id)
    db.delete(job)
    db.commit()
    return Response(status_code=204)


@app.post("/jobs/{job_id}/reports/draft", response_model=ReportOut, status_code=201)
def create_report_draft(job_id: int, payload: ReportDraftRequest, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    job = owned_job(db, job_id, user.id)
    # Local fallback makes the MVP testable without sending customer data externally.
    # Integrate a real AI provider only after reviewing privacy and retention terms.
    content = make_report_draft(payload.notes)
    import json
    report = ServiceReport(
        job_id=job.id,
        original_notes=payload.notes,
        generated_content=json.dumps(content, ensure_ascii=False),
        status="Draft",
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@app.patch("/reports/{report_id}", response_model=ReportOut)
def edit_report(report_id: int, payload: ReportEdit, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    report = owned_report(db, report_id, user.id)
    if report.status != "Draft":
        raise HTTPException(status_code=409, detail="Only draft reports can be edited")
    report.generated_content = payload.generated_content
    db.commit()
    db.refresh(report)
    return report


@app.post("/reports/{report_id}/approve", response_model=ReportOut)
def approve_report(report_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    report = owned_report(db, report_id, user.id)
    if report.status != "Draft":
        raise HTTPException(status_code=409, detail="Only draft reports can be approved")
    report.status = "Approved"
    db.commit()
    db.refresh(report)
    return report


@app.get("/reports/{report_id}/pdf")
def export_report_pdf(report_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    report = owned_report(db, report_id, user.id)
    if report.status != "Approved":
        raise HTTPException(status_code=409, detail="Only approved reports can be exported")
    job = owned_job(db, report.job_id, user.id)
    pdf_bytes = create_pdf(job.title, report.generated_content, report.original_notes)
    # Inline filename is static and content type is explicitly set.
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="tradedesk-report-{report.id}.pdf"'},
    )


@app.get("/jobs/{job_id}/tasks", response_model=list[TaskOut])
def list_tasks(job_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    owned_job(db, job_id, user.id)
    return list(db.scalars(select(Task).join(Job).where(Task.job_id == job_id, Job.user_id == user.id).order_by(Task.id.desc())))



@app.post("/jobs/{job_id}/tasks", response_model=TaskOut, status_code=201)
def create_task(
    job_id: int,
    payload: TaskCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    # Verify that the job belongs to the authenticated user.
    owned_job(db, job_id, user.id)

    # Normalize the task title.
    normalized_title = payload.title.strip()

    if not normalized_title:
        raise HTTPException(
            status_code=400,
            detail="Task title cannot be empty.",
        )

    # Check for an existing task with the same normalized title
    # within this job.
    existing_task = db.query(Task).filter(
        Task.job_id == job_id,
        func.lower(func.trim(Task.title)) == normalized_title.lower(),
    ).first()

    if existing_task:
        raise HTTPException(
            status_code=409,
            detail="A task with this title already exists for this job.",
        )

    # Create the task using the normalized title.
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
        )

    return task



@app.patch("/tasks/{task_id}", response_model=TaskOut)
def update_task(task_id: int, payload: TaskUpdate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    task = owned_task(db, task_id, user.id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(task, field, value)
    db.commit()
    db.refresh(task)
    return task
