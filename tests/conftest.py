
"""Test fixtures use an isolated temporary SQLite database."""
import os
import tempfile

import pytest

# Configure the test database before importing application modules.
_fd, _path = tempfile.mkstemp(prefix="tradedesk-test-", suffix=".db")
os.close(_fd)

os.environ["DATABASE_URL"] = f"sqlite:///{_path}"
os.environ["SECRET_KEY"] = "test-only-secret-key-that-is-not-for-production"
os.environ["ENVIRONMENT"] = "test"
# Keep tests independent of a developer's Redis: without this, REDIS_URL from
# .env made every auth request wait for a Redis connection (about 10 minutes
# per run on Windows when Redis was not running).
os.environ["REDIS_URL"] = ""

from fastapi.testclient import TestClient

from app.main import app
from app.database import Base, engine


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    with TestClient(app) as test_client:
        yield test_client

    Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def verification_emails(monkeypatch):
    """Capture verification emails without using a real SMTP server."""
    messages = []

    def fake_send_verification_email(recipient: str, token: str) -> None:
        messages.append({
            "recipient": recipient,
            "token": token,
        })

    monkeypatch.setattr(
        "app.main.send_verification_email",
        fake_send_verification_email,
    )

    return messages


@pytest.fixture()
def register_verified_user(client, verification_emails):
    """Register, verify, and log in any test user."""

    def _register(email: str, password: str):
        registration = client.post(
            "/auth/register",
            json={"email": email, "password": password},
        )

        assert registration.status_code == 201
        assert "access_token" not in registration.json()

        matching_emails = [
            item for item in verification_emails
            if item["recipient"] == email
        ]

        assert matching_emails, (
            f"No verification email captured for {email}"
        )

        verification_token = matching_emails[-1]["token"]

        verification = client.post(
            "/auth/verify-email",
            json={"token": verification_token, "password": password},
        )

        assert verification.status_code == 200

        login = client.post(
            "/auth/login",
            json={
                "email": email,
                "password": password,
            },
        )

        assert login.status_code == 200

        token = login.json()["access_token"]

        return {
            "token": token,
            "headers": {
                "Authorization": f"Bearer {token}",
            },
        }

    return _register


@pytest.fixture()
def account(client, verification_emails):
    """Create and authenticate the primary test account."""
    email = "owner@example.com"
    password = "a-long-test-password-123"

    registration = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": password,
        },
    )

    assert registration.status_code == 201
    assert "access_token" not in registration.json()

    assert len(verification_emails) == 1

    verification_token = verification_emails[0]["token"]

    verification = client.post(
        "/auth/verify-email",
        json={"token": verification_token, "password": password},
    )

    assert verification.status_code == 200

    login = client.post(
        "/auth/login",
        json={
            "email": email,
            "password": password,
        },
    )

    assert login.status_code == 200

    token = login.json()["access_token"]

    return {
        "client": client,
        "headers": {
            "Authorization": f"Bearer {token}",
        },
    }