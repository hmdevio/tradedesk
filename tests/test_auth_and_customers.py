
"""Authentication, validation, ownership, configuration, and rate-limit tests."""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request

import app.rate_limit as rate_limit
from app.config import Settings, get_settings
from app.database import SessionLocal
from app.models import AuthSession, Customer
from sqlalchemy.orm import Session


class FakeRedis:
    def __init__(self):
        self.counts = {}

    def eval(self, script, key_count, key, window_seconds):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key], window_seconds


def enable_fake_redis(monkeypatch):
    settings = rate_limit.get_settings()
    monkeypatch.setattr(settings, "redis_url", "redis://test")
    fake = FakeRedis()
    monkeypatch.setattr(rate_limit, "get_redis_client", lambda: fake)
    return fake


def make_request(peer, forwarded=None):
    headers = []

    if forwarded is not None:
        headers.append(
            (b"x-forwarded-for", forwarded.encode("ascii"))
        )

    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": headers,
        "client": (peer, 12345),
        "server": ("testserver", 80),
    })


# Authentication and account tests


def test_protected_endpoint_requires_auth(client):
    assert client.get("/customers").status_code == 401


def test_register_and_login(account):
    response = account["client"].post(
        "/auth/login",
        json={
            "email": "owner@example.com",
            "password": "a-long-test-password-123",
        },
    )

    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"


def test_short_password_rejected(client):
    response = client.post(
        "/auth/register",
        json={
            "email": "short@example.com",
            "password": "short",
        },
    )

    assert response.status_code == 422


# Customer and ownership tests


def test_customer_owner_isolation(account, register_verified_user):
    client = account["client"]

    created = client.post(
        "/customers",
        headers=account["headers"],
        json={"name": "Test Customer"},
    )

    assert created.status_code == 201

    other = register_verified_user(
        "other@example.com",
        "another-long-password-123",
    )

    assert client.get(
        f"/customers/{created.json()['id']}",
        headers=other["headers"],
    ).status_code == 404


def test_job_cannot_use_another_users_customer(
    account,
    register_verified_user,
):
    client = account["client"]

    created = client.post(
        "/customers",
        headers=account["headers"],
        json={"name": "Private Customer"},
    )

    assert created.status_code == 201

    other = register_verified_user(
        "other2@example.com",
        "another-long-password-456",
    )

    response = client.post(
        "/jobs",
        headers=other["headers"],
        json={
            "customer_id": created.json()["id"],
            "title": "Unauthorized job",
            "trade_type": "Plumbing",
        },
    )

    assert response.status_code == 404


# Rate-limit tests


def test_login_rate_limit_returns_429_and_retry_after(
    client,
    monkeypatch,
):
    fake = enable_fake_redis(monkeypatch)

    payload = {
        "email": "missing@example.com",
        "password": "wrong-password",
    }

    responses = [
        client.post("/auth/login", json=payload)
        for _ in range(6)
    ]

    assert [response.status_code for response in responses] == [
        401, 401, 401, 401, 401, 429
    ]

    assert responses[-1].headers["Retry-After"] == "900"
    assert all(
        "203.0.113.1" not in key
        for key in fake.counts
    )


def test_registration_rate_limit_returns_429(client, monkeypatch):
    enable_fake_redis(monkeypatch)

    # Keep this test focused on rate limiting.
    # Do not require a real SMTP server for registration.
    monkeypatch.setattr(
        "app.main.send_verification_email",
        lambda recipient, token: None,
    )

    responses = [
        client.post(
            "/auth/register",
            json={
                "email": f"rate-{number}@example.com",
                "password": "a-long-test-password-123",
            },
        )
        for number in range(4)
    ]

    assert [response.status_code for response in responses] == [
        201, 201, 201, 429
    ]

    assert responses[-1].headers["Retry-After"] == "3600"


def test_production_rate_limiter_fails_closed_without_redis(
    client,
    monkeypatch,
):
    settings = rate_limit.get_settings()

    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "redis_url", "")

    response = client.post(
        "/auth/login",
        json={
            "email": "missing@example.com",
            "password": "wrong-password",
        },
    )

    assert response.status_code == 503


# Trusted proxy tests


def test_trusted_proxy_without_forwarded_header_uses_peer_ip(monkeypatch):
    monkeypatch.setattr(
        get_settings(),
        "trusted_proxy_cidrs",
        "10.0.0.0/8",
    )

    assert rate_limit.client_ip(
        make_request("10.0.0.2")
    ) == "10.0.0.2"


def test_trusted_proxy_chain_resolves_original_client(monkeypatch):
    monkeypatch.setattr(
        get_settings(),
        "trusted_proxy_cidrs",
        "10.0.0.0/8",
    )

    assert rate_limit.client_ip(
        make_request(
            "10.0.0.2",
            "203.0.113.8, 10.0.0.1",
        )
    ) == "203.0.113.8"


def test_untrusted_peer_cannot_spoof_forwarded_client_ip(monkeypatch):
    monkeypatch.setattr(
        get_settings(),
        "trusted_proxy_cidrs",
        "10.0.0.0/8",
    )

    assert rate_limit.client_ip(
        make_request(
            "198.51.100.4",
            "203.0.113.8",
        )
    ) == "198.51.100.4"


def test_malformed_forwarded_chain_is_rejected(monkeypatch):
    monkeypatch.setattr(
        get_settings(),
        "trusted_proxy_cidrs",
        "10.0.0.0/8",
    )

    with pytest.raises(HTTPException) as error:
        rate_limit.client_ip(
            make_request(
                "10.0.0.2",
                "not-an-ip",
            )
        )

    assert error.value.status_code == 400


# JWT validation tests


@pytest.mark.parametrize(
    "token_kind",
    ["malformed", "expired", "invalid_signature"],
)
def test_invalid_jwt_is_rejected(client, token_kind):
    settings = get_settings()

    if token_kind == "malformed":
        token = "this-is-not-a-jwt"

    else:
        now = datetime.now(timezone.utc)

        if token_kind == "expired":
            payload = {
                "sub": "1",
                "iat": now - timedelta(hours=2),
                "exp": now - timedelta(hours=1),
            }
            key = settings.secret_key

        else:
            payload = {
                "sub": "1",
                "iat": now,
                "exp": now + timedelta(minutes=5),
            }
            key = "wrong-signing-key-for-test-only-32-bytes-minimum"

        token = jwt.encode(
            payload,
            key,
            algorithm="HS256",
        )

    response = client.get(
        "/customers",
        headers={
            "Authorization": f"Bearer {token}"
        },
    )

    assert response.status_code == 401


# Redis security tests


def test_production_redis_requires_tls_and_authentication():
    with pytest.raises(RuntimeError, match="rediss"):
        rate_limit._validate_production_redis_url(
            "redis://:password@redis.internal:6379/0"
        )


def test_production_redis_rejects_disabled_certificate_validation():
    with pytest.raises(RuntimeError, match="certificate verification"):
        rate_limit._validate_production_redis_url(
            "rediss://:password@redis.internal:6379/0"
            "?ssl_cert_reqs=none"
        )


# Session management tests


def test_logout_revokes_only_the_current_session(account):
    client = account["client"]

    second_login = client.post(
        "/auth/login",
        json={
            "email": "owner@example.com",
            "password": "a-long-test-password-123",
        },
    )

    second_token = second_login.json()["access_token"]

    logout_response = client.post(
        "/auth/logout",
        headers=account["headers"],
    )

    assert logout_response.status_code == 204

    assert client.get(
        "/customers",
        headers=account["headers"],
    ).status_code == 401

    assert client.get(
        "/customers",
        headers={
            "Authorization": f"Bearer {second_token}"
        },
    ).status_code == 200


def test_password_change_revokes_all_account_sessions(account):
    client = account["client"]

    second_login = client.post(
        "/auth/login",
        json={
            "email": "owner@example.com",
            "password": "a-long-test-password-123",
        },
    )

    second_headers = {
        "Authorization": (
            f"Bearer {second_login.json()['access_token']}"
        )
    }

    response = client.post(
        "/auth/password",
        headers=account["headers"],
        json={
            "current_password": "a-long-test-password-123",
            "new_password": "a-new-long-password-456",
        },
    )

    assert response.status_code == 204

    assert client.get(
        "/customers",
        headers=account["headers"],
    ).status_code == 401

    assert client.get(
        "/customers",
        headers=second_headers,
    ).status_code == 401

    login = client.post(
        "/auth/login",
        json={
            "email": "owner@example.com",
            "password": "a-new-long-password-456",
        },
    )

    assert login.status_code == 200


def test_password_change_rejects_wrong_current_password(account):
    response = account["client"].post(
        "/auth/password",
        headers=account["headers"],
        json={
            "current_password": "incorrect-current-password",
            "new_password": "a-new-long-password-456",
        },
    )

    assert response.status_code == 400

    assert account["client"].get(
        "/customers",
        headers=account["headers"],
    ).status_code == 200


def test_session_expiration_is_enforced(account):
    client = account["client"]

    with SessionLocal() as db:
        session = db.query(AuthSession).one()
        session.expires_at = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        db.commit()

    assert client.get(
        "/customers",
        headers=account["headers"],
    ).status_code == 401

def test_login_removes_expired_sessions(account):
    client = account["client"]

    with SessionLocal() as db:
        session = db.query(AuthSession).one()
        session.expires_at = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        )
        db.commit()

    login = client.post(
        "/auth/login",
        json={
            "email": "owner@example.com",
            "password": "a-long-test-password-123",
        },
    )

    assert login.status_code == 200

    with SessionLocal() as db:
        sessions = db.query(AuthSession).all()

        assert len(sessions) == 1
        assert sessions[0].expires_at is not None
        assert sessions[0].expires_at > datetime.now(timezone.utc).replace(
            tzinfo=None
        )

def test_session_cannot_be_reassigned_to_another_user(
    account,
    register_verified_user,
):
    client = account["client"]

    second = register_verified_user(
        "session-other@example.com",
        "another-long-password-123",
    )

    second_user_id = int(
        jwt.decode(
            second["token"],
            get_settings().secret_key,
            algorithms=["HS256"],
        )["sub"]
    )

    first_payload = jwt.decode(
        account["headers"]["Authorization"].split(" ", 1)[1],
        get_settings().secret_key,
        algorithms=["HS256"],
    )

    forged = jwt.encode(
        {
            **first_payload,
            "sub": str(second_user_id),
        },
        get_settings().secret_key,
        algorithm="HS256",
    )

    response = client.get(
        "/customers",
        headers={
            "Authorization": f"Bearer {forged}"
        },
    )

    assert response.status_code == 401


# Production application and email configuration tests


def valid_production_settings(**overrides):
    """Return a valid baseline production configuration for testing."""

    settings = {
        "environment": "production",
        "app_base_url": "https://tradedesk.example.com",
        "email_verification_minutes": 30,
        "smtp_host": "smtp.example.com",
        "smtp_port": 587,
        "smtp_username": "test-user",
        "smtp_password": "test-password",
        "smtp_from_email": "noreply@example.com",
        "smtp_use_starttls": True,
        "smtp_use_ssl": False,
    }

    settings.update(overrides)

    return Settings(
        _env_file=None,
        **settings,
    )


def test_production_configuration_accepts_valid_email_settings():
    settings = valid_production_settings()

    assert settings.environment == "production"
    assert settings.app_base_url == "https://tradedesk.example.com"
    assert settings.smtp_use_starttls is True
    assert settings.email_verification_minutes == 30


@pytest.mark.parametrize(
    "app_base_url",
    [
        "http://tradedesk.example.com",
        "tradedesk.example.com",
        "https://",
        "https://user:password@tradedesk.example.com",
        "https://tradedesk.example.com/?token=unexpected",
        "https://tradedesk.example.com/#unexpected",
    ],
)
def test_production_rejects_unsafe_application_urls(app_base_url):
    with pytest.raises(ValidationError, match="APP_BASE_URL"):
        valid_production_settings(
            app_base_url=app_base_url,
        )


@pytest.mark.parametrize(
    "overrides, expected_error",
    [
        (
            {"smtp_host": ""},
            "SMTP_HOST",
        ),
        (
            {"smtp_from_email": ""},
            "SMTP_FROM_EMAIL",
        ),
    ],
)
def test_production_requires_smtp_configuration(
    overrides,
    expected_error,
):
    with pytest.raises(
        ValidationError,
        match=expected_error,
    ):
        valid_production_settings(**overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {
            "smtp_username": "test-user",
            "smtp_password": "",
        },
        {
            "smtp_username": "",
            "smtp_password": "test-password",
        },
    ],
)
def test_smtp_credentials_must_be_configured_together(overrides):
    with pytest.raises(
        ValidationError,
        match="configured together",
    ):
        valid_production_settings(**overrides)


def test_smtp_authentication_requires_encryption():
    with pytest.raises(
        ValidationError,
        match="requires SSL or STARTTLS",
    ):
        valid_production_settings(
            smtp_use_starttls=False,
            smtp_use_ssl=False,
        )


def test_smtp_rejects_conflicting_encryption_modes():
    with pytest.raises(
        ValidationError,
        match="not both",
    ):
        valid_production_settings(
            smtp_use_starttls=True,
            smtp_use_ssl=True,
        )


@pytest.mark.parametrize(
    "smtp_port",
    [0, -1, 65536],
)
def test_smtp_rejects_invalid_ports(smtp_port):
    with pytest.raises(
        ValidationError,
        match="SMTP_PORT",
    ):
        valid_production_settings(
            smtp_port=smtp_port,
        )


@pytest.mark.parametrize(
    "expiration",
    [0, -1, -30],
)
def test_email_verification_requires_positive_expiration(expiration):
    with pytest.raises(
        ValidationError,
        match="EMAIL_VERIFICATION_MINUTES",
    ):
        valid_production_settings(
            email_verification_minutes=expiration,
        )


def test_development_allows_local_http_without_smtp():
    settings = Settings(
        _env_file=None,
        environment="development",
        app_base_url="http://localhost:8000",
        smtp_host="",
        smtp_from_email="",
    )

    assert settings.environment == "development"
    assert settings.app_base_url == "http://localhost:8000"


def test_production_smtp_requires_encryption():
    """Production SMTP must reject unencrypted delivery without authentication."""
    with pytest.raises(
        ValidationError,
        match="Production SMTP requires SSL or STARTTLS",
    ):
        valid_production_settings(
            smtp_username="",
            smtp_password="",
            smtp_use_ssl=False,
            smtp_use_starttls=False,
        )


# Customer email uniqueness tests


def test_customer_create_rejects_normalized_duplicate_email(account):
    client = account["client"]

    first = client.post(
        "/customers",
        headers=account["headers"],
        json={
            "name": "First Customer",
            "email": "client@example.com",
        },
    )

    assert first.status_code == 201

    duplicate = client.post(
        "/customers",
        headers=account["headers"],
        json={
            "name": "Duplicate Customer",
            "email": "  CLIENT@example.com  ",
        },
    )

    assert duplicate.status_code == 409


def test_customer_update_rejects_another_customers_email(account):
    client = account["client"]

    first = client.post(
        "/customers",
        headers=account["headers"],
        json={
            "name": "First Customer",
            "email": "first@example.com",
        },
    )

    second = client.post(
        "/customers",
        headers=account["headers"],
        json={
            "name": "Second Customer",
            "email": "second@example.com",
        },
    )

    assert first.status_code == 201
    assert second.status_code == 201

    response = client.patch(
        f"/customers/{second.json()['id']}",
        headers=account["headers"],
        json={"email": " FIRST@example.com "},
    )

    assert response.status_code == 409


def test_customer_email_can_be_cleared_with_null(account):
    client = account["client"]

    created = client.post(
        "/customers",
        headers=account["headers"],
        json={
            "name": "Customer With Email",
            "email": "clear@example.com",
        },
    )

    assert created.status_code == 201

    response = client.patch(
        f"/customers/{created.json()['id']}",
        headers=account["headers"],
        json={"email": None},
    )

    assert response.status_code == 200
    assert response.json()["email"] is None


def test_same_customer_email_is_allowed_for_different_accounts(
    account,
    register_verified_user,
):
    client = account["client"]

    first = client.post(
        "/customers",
        headers=account["headers"],
        json={
            "name": "First Account Customer",
            "email": "shared@example.com",
        },
    )

    assert first.status_code == 201

    second_account = register_verified_user(
        "customer-owner@example.com",
        "another-long-password-123",
    )

    second = client.post(
        "/customers",
        headers=second_account["headers"],
        json={
            "name": "Second Account Customer",
            "email": "SHARED@example.com",
        },
    )

    assert second.status_code == 201
    assert second.json()["email"] == "shared@example.com"


def test_customer_create_handles_database_unique_conflict(
    account,
    monkeypatch,
):
    client = account["client"]

    token = account["headers"]["Authorization"].split(" ", 1)[1]
    user_id = int(
        jwt.decode(
            token,
            get_settings().secret_key,
            algorithms=["HS256"],
        )["sub"]
    )

    original_commit = Session.commit
    conflict_inserted = False

    def commit_with_concurrent_insert(db_session):
        nonlocal conflict_inserted

        has_new_customer = any(
            isinstance(item, Customer)
            for item in db_session.new
        )

        if has_new_customer and not conflict_inserted:
            conflict_inserted = True

            # Simulate another request inserting the same email
            # after the endpoint's duplicate check.
            with SessionLocal() as concurrent_db:
                concurrent_db.add(
                    Customer(
                        user_id=user_id,
                        name="Concurrent Customer",
                        email="race@example.com",
                    )
                )
                concurrent_db.commit()

        return original_commit(db_session)

    monkeypatch.setattr(
        Session,
        "commit",
        commit_with_concurrent_insert,
    )

    response = client.post(
        "/customers",
        headers=account["headers"],
        json={
            "name": "Racing Customer",
            "email": "race@example.com",
        },
    )

    assert conflict_inserted is True
    assert response.status_code == 409
