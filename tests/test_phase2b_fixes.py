"""Regression tests for Audit remediation Phase 2b (security hardening).

S5 safe configuration, password check at email verification (closes the N1
residual), S9 per-account throttling, absolute session limit, S13 pagination.
"""
from datetime import datetime, timedelta, timezone
import itertools

import jwt
import pytest
from pydantic import ValidationError

from app import rate_limit
from app.config import Settings, get_settings
from app.security import ALGORITHM, create_access_token


PASSWORD = "a-long-test-password-123"
GOOD_SECRET = "x" * 40


# S5: configuration


def make_settings(monkeypatch, **values):
    """Build Settings from explicit values only (no .env, no test env vars)."""
    for name in ("ENVIRONMENT", "SECRET_KEY", "REDIS_URL", "DATABASE_URL"):
        monkeypatch.delenv(name, raising=False)
    return Settings(_env_file=None, **values)


def test_environment_must_be_set(monkeypatch):
    with pytest.raises(ValidationError, match="ENVIRONMENT must be set"):
        make_settings(monkeypatch, secret_key=GOOD_SECRET)


@pytest.mark.parametrize("value", ["prod", "staging", "", "   "])
def test_unknown_environment_is_rejected(monkeypatch, value):
    with pytest.raises(ValidationError, match="ENVIRONMENT must be set"):
        make_settings(monkeypatch, environment=value, secret_key=GOOD_SECRET)


def test_environment_is_normalized(monkeypatch):
    settings = make_settings(
        monkeypatch, environment=" Development ", secret_key=GOOD_SECRET
    )
    assert settings.environment == "development"


@pytest.mark.parametrize(
    "secret",
    ["", "short-secret", "replace-with-a-long-random-secret-before-running"],
)
def test_weak_secret_is_rejected_in_development_too(monkeypatch, secret):
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        make_settings(monkeypatch, environment="development", secret_key=secret)


def test_token_lifetime_cannot_exceed_session_limit(monkeypatch):
    with pytest.raises(ValidationError, match="ACCESS_TOKEN_MINUTES"):
        make_settings(
            monkeypatch,
            environment="development",
            secret_key=GOOD_SECRET,
            access_token_minutes=120,
            session_max_hours=1,
        )


# Email verification needs the registration password


def test_verification_requires_the_registration_password(
    client, verification_emails
):
    email = "new@example.com"
    client.post("/auth/register", json={"email": email, "password": PASSWORD})
    token = verification_emails[-1]["token"]

    wrong = client.post(
        "/auth/verify-email",
        json={"token": token, "password": "not-the-password"},
    )
    assert wrong.status_code == 400
    assert "password" in wrong.json()["detail"].lower()

    # A wrong password does not use up the link.
    right = client.post(
        "/auth/verify-email", json={"token": token, "password": PASSWORD}
    )
    assert right.status_code == 200
    login = client.post(
        "/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert login.status_code == 200


def test_stranger_clicking_the_link_cannot_verify_the_account(
    client, verification_emails
):
    """N1 residual: someone registers your email; you click the link."""
    victim = "victim@example.com"
    attacker_password = "attacker-chosen-password"
    client.post(
        "/auth/register",
        json={"email": victim, "password": attacker_password},
    )
    link = verification_emails[-1]["token"]

    # The inbox owner doesn't know the attacker's password.
    attempt = client.post(
        "/auth/verify-email",
        json={"token": link, "password": "whatever-the-victim-tries"},
    )
    assert attempt.status_code == 400

    # The account stays unverified, so the attacker still cannot sign in.
    login = client.post(
        "/auth/login", json={"email": victim, "password": attacker_password}
    )
    assert login.status_code == 403


def test_verification_without_password_is_rejected(client):
    response = client.post("/auth/verify-email", json={"token": "x" * 48})
    assert response.status_code == 422


# S9: per-account throttling


class FakeRedis:
    """Counts like the Lua script in app/rate_limit.py."""

    def __init__(self):
        self.counts = {}

    def eval(self, script, numkeys, key, window):
        self.counts[key] = self.counts.get(key, 0) + 1
        return [self.counts[key], window]


@pytest.fixture()
def redis_limits(monkeypatch):
    """Turn rate limiting on with an in-memory store and rotating client IPs."""
    monkeypatch.setattr(get_settings(), "redis_url", "redis://fake")
    fake = FakeRedis()
    monkeypatch.setattr(rate_limit, "get_redis_client", lambda: fake)
    addresses = (f"198.51.100.{n}" for n in itertools.count(1))
    monkeypatch.setattr(rate_limit, "client_ip", lambda request: next(addresses))
    return fake


def test_login_limit_is_per_account_across_ip_addresses(client, redis_limits):
    statuses = [
        client.post(
            "/auth/login",
            json={"email": "target@example.com", "password": "guess-" + str(n)},
        ).status_code
        for n in range(11)
    ]
    # Every attempt came from a new IP, yet the 11th is refused.
    assert statuses[:10] == [401] * 10
    assert statuses[10] == 429


def test_login_limit_does_not_affect_other_accounts(client, redis_limits):
    for n in range(11):
        client.post(
            "/auth/login",
            json={"email": "target@example.com", "password": "guess-" + str(n)},
        )
    other = client.post(
        "/auth/login",
        json={"email": "someone-else@example.com", "password": "guess"},
    )
    assert other.status_code == 401


def test_password_reset_emails_are_limited_per_address(client, redis_limits):
    statuses = [
        client.post(
            "/auth/forgot-password", json={"email": "target@example.com"}
        ).status_code
        for _ in range(4)
    ]
    assert statuses == [200, 200, 200, 429]


def test_password_change_attempts_are_limited(account, redis_limits):
    client = account["client"]
    statuses = [
        client.post(
            "/auth/password",
            headers=account["headers"],
            json={
                "current_password": "wrong-password-" + str(n),
                "new_password": "a-brand-new-password-1",
            },
        ).status_code
        for n in range(6)
    ]
    assert statuses == [400] * 5 + [429]


# Absolute session limit


def token_for(account_headers, auth_time):
    """Re-sign the account's live session with a chosen sign-in time."""
    token = account_headers["Authorization"].split()[1]
    payload = jwt.decode(
        token, get_settings().secret_key, algorithms=[ALGORITHM]
    )
    forged = create_access_token(
        int(payload["sub"]),
        payload["jti"],
        datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
        auth_time,
    )
    return {"Authorization": f"Bearer {forged}"}


def test_tokens_carry_the_sign_in_time(account):
    token = account["headers"]["Authorization"].split()[1]
    payload = jwt.decode(
        token, get_settings().secret_key, algorithms=[ALGORITHM]
    )
    assert abs(payload["auth_time"] - datetime.now(timezone.utc).timestamp()) < 60


def test_refresh_keeps_the_original_sign_in_time(account):
    client = account["client"]
    signed_in = datetime.now(timezone.utc) - timedelta(hours=3)
    refreshed = client.post(
        "/auth/refresh", headers=token_for(account["headers"], signed_in)
    )
    assert refreshed.status_code == 200
    payload = jwt.decode(
        refreshed.json()["access_token"],
        get_settings().secret_key,
        algorithms=[ALGORITHM],
    )
    assert payload["auth_time"] == int(signed_in.timestamp())


def test_refresh_is_shortened_near_the_session_limit(account):
    client = account["client"]
    signed_in = datetime.now(timezone.utc) - timedelta(hours=11, minutes=50)
    refreshed = client.post(
        "/auth/refresh", headers=token_for(account["headers"], signed_in)
    )
    assert refreshed.status_code == 200
    assert refreshed.json()["expires_in_seconds"] <= 10 * 60


def test_refresh_is_refused_after_the_session_limit(account):
    client = account["client"]
    signed_in = datetime.now(timezone.utc) - timedelta(hours=13)
    refreshed = client.post(
        "/auth/refresh", headers=token_for(account["headers"], signed_in)
    )
    assert refreshed.status_code == 401
    assert "limit" in refreshed.json()["detail"].lower()


# S13: pagination


def test_lists_are_paginated(account):
    client = account["client"]
    headers = account["headers"]
    for n in range(3):
        client.post("/customers", headers=headers, json={"name": f"Customer {n}"})

    first = client.get("/customers?limit=2", headers=headers).json()
    rest = client.get("/customers?limit=2&offset=2", headers=headers).json()
    assert len(first) == 2
    assert len(rest) == 1
    assert {c["id"] for c in first}.isdisjoint({c["id"] for c in rest})


@pytest.mark.parametrize("query", ["limit=0", "limit=201", "offset=-1"])
def test_page_bounds_are_enforced(account, query):
    response = account["client"].get(
        f"/customers?{query}", headers=account["headers"]
    )
    assert response.status_code == 422
