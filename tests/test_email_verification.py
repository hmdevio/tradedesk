
"""Email verification workflow and security tests."""

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from app.database import SessionLocal
from app.models import EmailVerificationToken, User


def register_unverified_user(client, email="verify@example.com"):
    """Register a user and return the response."""
    return client.post(
        "/auth/register",
        json={
            "email": email,
            "password": "a-long-test-password-123",
        },
    )


def login_user(client, email="verify@example.com"):
    """Attempt to log in with the test user's credentials."""
    return client.post(
        "/auth/login",
        json={
            "email": email,
            "password": "a-long-test-password-123",
        },
    )


def test_registration_creates_unverified_user_without_login_token(
    client,
    verification_emails,
):
    response = register_unverified_user(client)

    assert response.status_code == 201
    assert "access_token" not in response.json()
    assert "token_type" not in response.json()

    with SessionLocal() as db:
        user = db.query(User).filter_by(
            email="verify@example.com"
        ).one()

        assert user.email_verified is False
        assert user.email_verified_at is None

    assert len(verification_emails) == 1
    assert verification_emails[0]["recipient"] == "verify@example.com"
    assert verification_emails[0]["token"]


def test_unverified_user_cannot_log_in(
    client,
    verification_emails,
):
    registration = register_unverified_user(client)

    assert registration.status_code == 201

    response = login_user(client)

    assert response.status_code == 403
    assert "access_token" not in response.json()


def test_verification_token_hash_is_stored_instead_of_plaintext(
    client,
    verification_emails,
):
    response = register_unverified_user(client)

    assert response.status_code == 201

    plaintext_token = verification_emails[0]["token"]
    expected_hash = hashlib.sha256(
        plaintext_token.encode("utf-8")
    ).hexdigest()

    with SessionLocal() as db:
        stored_token = db.query(
            EmailVerificationToken
        ).one()

        assert stored_token.token_hash == expected_hash
        assert stored_token.token_hash != plaintext_token


def test_valid_verification_token_verifies_account(
    client,
    verification_emails,
):
    registration = register_unverified_user(client)

    assert registration.status_code == 201

    token = verification_emails[0]["token"]

    response = client.post(
        "/auth/verify-email",
        json={"token": token},
    )

    assert response.status_code == 200

    with SessionLocal() as db:
        user = db.query(User).filter_by(
            email="verify@example.com"
        ).one()

        stored_token = db.query(
            EmailVerificationToken
        ).one()

        assert user.email_verified is True
        assert user.email_verified_at is not None
        assert stored_token.used_at is not None


def test_verified_user_can_log_in(
    client,
    verification_emails,
):
    registration = register_unverified_user(client)

    assert registration.status_code == 201

    token = verification_emails[0]["token"]

    verification = client.post(
        "/auth/verify-email",
        json={"token": token},
    )

    assert verification.status_code == 200

    login = login_user(client)

    assert login.status_code == 200
    assert login.json()["token_type"] == "bearer"
    assert login.json()["access_token"]


def test_invalid_verification_token_is_rejected(client):
    response = client.post(
        "/auth/verify-email",
        json={"token": "x" * 48},
    )

    assert response.status_code == 400


def test_expired_verification_token_is_rejected(
    client,
    verification_emails,
):
    registration = register_unverified_user(client)

    assert registration.status_code == 201

    token = verification_emails[0]["token"]

    with SessionLocal() as db:
        stored_token = db.query(
            EmailVerificationToken
        ).one()

        stored_token.expires_at = (
            datetime.now(timezone.utc) - timedelta(minutes=1)
        )

        db.commit()

    response = client.post(
        "/auth/verify-email",
        json={"token": token},
    )

    assert response.status_code == 400

    with SessionLocal() as db:
        user = db.query(User).filter_by(
            email="verify@example.com"
        ).one()

        assert user.email_verified is False


def test_verification_token_cannot_be_reused(
    client,
    verification_emails,
):
    registration = register_unverified_user(client)

    assert registration.status_code == 201

    token = verification_emails[0]["token"]

    first_response = client.post(
        "/auth/verify-email",
        json={"token": token},
    )

    second_response = client.post(
        "/auth/verify-email",
        json={"token": token},
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 400


def test_resending_verification_rotates_previous_token(
    client,
    verification_emails,
):
    registration = register_unverified_user(client)

    assert registration.status_code == 201
    assert len(verification_emails) == 1

    old_token = verification_emails[0]["token"]

    resend = client.post(
        "/auth/resend-verification",
        json={"email": "verify@example.com"},
    )

    assert resend.status_code == 200
    assert len(verification_emails) == 2

    new_token = verification_emails[1]["token"]

    assert new_token != old_token

    old_verification = client.post(
        "/auth/verify-email",
        json={"token": old_token},
    )

    new_verification = client.post(
        "/auth/verify-email",
        json={"token": new_token},
    )

    assert old_verification.status_code == 400
    assert new_verification.status_code == 200


def test_resend_response_does_not_reveal_account_existence(
    client,
    verification_emails,
):
    registration = register_unverified_user(client)

    assert registration.status_code == 201

    existing_response = client.post(
        "/auth/resend-verification",
        json={"email": "verify@example.com"},
    )

    missing_response = client.post(
        "/auth/resend-verification",
        json={"email": "missing@example.com"},
    )

    assert existing_response.status_code == 200
    assert missing_response.status_code == 200
    assert existing_response.json() == missing_response.json()


def test_resend_does_not_send_email_for_verified_account(
    client,
    verification_emails,
):
    registration = register_unverified_user(client)

    assert registration.status_code == 201

    token = verification_emails[0]["token"]

    verification = client.post(
        "/auth/verify-email",
        json={"token": token},
    )

    assert verification.status_code == 200

    original_email_count = len(verification_emails)

    response = client.post(
        "/auth/resend-verification",
        json={"email": "verify@example.com"},
    )

    assert response.status_code == 200
    assert len(verification_emails) == original_email_count


def test_registration_smtp_failure_returns_generic_error(
    client,
    monkeypatch,
):
    def fail_email_delivery(recipient, token):
        raise RuntimeError("Sensitive SMTP connection details")

    monkeypatch.setattr(
        "app.main.send_verification_email",
        fail_email_delivery,
    )

    response = register_unverified_user(client)

    assert response.status_code == 503
    assert "Sensitive SMTP connection details" not in response.text

    # Registration is retained so the user can request another email.
    with SessionLocal() as db:
        user = db.query(User).filter_by(
            email="verify@example.com"
        ).one()

        assert user.email_verified is False


def test_smtp_failure_does_not_expose_token_or_credentials(
    client,
    monkeypatch,
):
    def fail_email_delivery(recipient, token):
        raise RuntimeError(
            "SMTP_PASSWORD=secret SMTP connection failed"
        )

    monkeypatch.setattr(
        "app.main.send_verification_email",
        fail_email_delivery,
    )

    response = register_unverified_user(client)

    assert response.status_code == 503
    assert "secret" not in response.text
    assert "SMTP_PASSWORD" not in response.text
    assert "SMTP connection failed" not in response.text


@pytest.mark.parametrize(
    ("smtp_host", "smtp_from_email"),
    [
        ("", "noreply@tradedesk.local"),
        ("127.0.0.1", ""),
    ],
)
def test_email_delivery_rejects_missing_smtp_configuration(
    monkeypatch,
    smtp_host,
    smtp_from_email,
):
    from app import email_delivery
    from app.config import Settings

    settings = Settings(
        _env_file=None,
        environment="development",
        app_base_url="http://localhost:8000",
        smtp_host=smtp_host,
        smtp_from_email=smtp_from_email,
    )

    monkeypatch.setattr(
        email_delivery,
        "get_settings",
        lambda: settings,
    )

    with pytest.raises(
        RuntimeError,
        match="Email delivery is not configured",
    ):
        email_delivery.send_verification_email(
            "test@example.com",
            "test-token",
        )
