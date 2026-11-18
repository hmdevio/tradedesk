"""Regression tests for Audit remediation Phase 2a (2026-11-18 re-audit).

N1/S4/S7 registering an email that already has an account, S10/U9
readable validation errors without echoed input, S8 production check in
the rate limiter.
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app import rate_limit
from app.config import get_settings


PASSWORD = "a-long-test-password-123"
REGISTRATION_MESSAGE = (
    "Account created. Check your email to verify your address "
    "before signing in."
)


@pytest.fixture()
def setup_emails(monkeypatch):
    """Capture existing-account setup emails without SMTP."""
    messages = []

    def fake_send(recipient: str, token: str) -> None:
        messages.append({"recipient": recipient, "token": token})

    monkeypatch.setattr("app.main.send_existing_account_email", fake_send)
    return messages


def login(client, email, password):
    return client.post(
        "/auth/login", json={"email": email, "password": password}
    )


# N1: someone registers after the real owner


def test_reregistering_does_not_change_the_password(
    client, verification_emails, setup_emails
):
    email = "victim@example.com"
    owner_password = "owners-own-password-1"
    attacker_password = "attacker-chosen-password"

    first = client.post(
        "/auth/register", json={"email": email, "password": owner_password}
    )
    assert first.status_code == 201
    owner_link = verification_emails[-1]["token"]

    second = client.post(
        "/auth/register", json={"email": email, "password": attacker_password}
    )
    assert second.status_code == 201
    assert second.json()["message"] == REGISTRATION_MESSAGE

    # No new verification link; the owner gets a setup link instead.
    assert len(verification_emails) == 1
    assert [m["recipient"] for m in setup_emails] == [email]

    # Pending verification links are voided, so the account can only be
    # finished through the emailed setup link.
    assert client.post(
        "/auth/verify-email", json={"token": owner_link}
    ).status_code == 400

    # The second registrant's password never works.
    assert login(client, email, attacker_password).status_code == 401


def test_setup_link_lets_the_inbox_owner_choose_the_password(
    client, verification_emails, setup_emails
):
    email = "victim@example.com"
    client.post(
        "/auth/register",
        json={"email": email, "password": "attacker-chosen-password"},
    )
    client.post(
        "/auth/register",
        json={"email": email, "password": "owners-own-password-1"},
    )

    reset = client.post("/auth/reset-password", json={
        "token": setup_emails[-1]["token"],
        "new_password": "owner-picked-password-2",
    })
    assert reset.status_code == 200

    assert login(client, email, "attacker-chosen-password").status_code == 401
    assert login(client, email, "owner-picked-password-2").status_code == 200


# S7: registration no longer reveals verified accounts


def test_registering_a_verified_email_looks_like_a_new_registration(
    account, setup_emails
):
    client = account["client"]
    new = client.post(
        "/auth/register",
        json={"email": "someone-new@example.com", "password": PASSWORD},
    )
    existing = client.post(
        "/auth/register",
        json={"email": " Owner@Example.com ", "password": "someone-else-pass"},
    )

    assert new.status_code == existing.status_code == 201
    assert new.json() == existing.json()
    assert [m["recipient"] for m in setup_emails] == ["owner@example.com"]

    # The owner's password and session are untouched.
    assert login(client, "owner@example.com", PASSWORD).status_code == 200
    assert client.get("/customers", headers=account["headers"]).status_code == 200


def test_setup_email_failure_still_returns_the_generic_response(
    client, verification_emails, monkeypatch
):
    def fail(recipient: str, token: str) -> None:
        raise RuntimeError("smtp down")

    monkeypatch.setattr("app.main.send_existing_account_email", fail)
    client.post(
        "/auth/register",
        json={"email": "dup@example.com", "password": PASSWORD},
    )
    again = client.post(
        "/auth/register",
        json={"email": "dup@example.com", "password": PASSWORD},
    )
    assert again.status_code == 201
    assert again.json()["message"] == REGISTRATION_MESSAGE


# S10 / U9: validation errors


def test_validation_errors_do_not_echo_submitted_values(client):
    secret = "p" * 200
    response = client.post(
        "/auth/login", json={"email": "a@example.com", "password": secret}
    )
    assert response.status_code == 422
    assert secret[:20] not in response.text
    body = response.json()
    assert isinstance(body["detail"], str)
    assert body["detail"].startswith("Password:")
    assert body["errors"][0]["field"] == "password"
    assert "input" not in body["errors"][0]


def test_validation_errors_are_readable(account):
    client = account["client"]
    response = client.post(
        "/customers",
        headers=account["headers"],
        json={"name": "Dana", "email": "dana@"},
    )
    assert response.status_code == 422
    assert response.json()["detail"].startswith("Email:")
    assert "dana@" not in response.text


# S8: rate limiter production check


@pytest.mark.parametrize("value", ["production", "Production", " PRODUCTION "])
def test_rate_limit_fails_closed_for_any_production_spelling(
    monkeypatch, value
):
    settings = get_settings()
    monkeypatch.setattr(settings, "environment", value)
    monkeypatch.setattr(settings, "redis_url", "")
    request = SimpleNamespace(
        client=SimpleNamespace(host="203.0.113.5"), headers={}
    )
    with pytest.raises(HTTPException) as caught:
        rate_limit.enforce_rate_limit(request, "login", 5, 900)
    assert caught.value.status_code == 503
