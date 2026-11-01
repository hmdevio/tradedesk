"""Authentication, validation, ownership, and rate-limit tests."""
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from fastapi import HTTPException
from starlette.requests import Request

import app.rate_limit as rate_limit
from app.config import get_settings


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
        headers.append((b"x-forwarded-for", forwarded.encode("ascii")))
    return Request({
        "type": "http", "http_version": "1.1", "method": "GET", "scheme": "http",
        "path": "/", "raw_path": b"/", "query_string": b"", "headers": headers,
        "client": (peer, 12345), "server": ("testserver", 80),
    })


def test_protected_endpoint_requires_auth(client):
    assert client.get("/customers").status_code == 401


def test_register_and_login(account):
    response = account["client"].post("/auth/login", json={
        "email": "owner@example.com", "password": "a-long-test-password-123",
    })
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"


def test_short_password_rejected(client):
    response = client.post("/auth/register", json={"email": "short@example.com", "password": "short"})
    assert response.status_code == 422


def test_customer_owner_isolation(account):
    client = account["client"]
    created = client.post("/customers", headers=account["headers"], json={"name": "Test Customer"})
    assert created.status_code == 201
    second = client.post("/auth/register", json={
        "email": "other@example.com", "password": "another-long-password-123",
    })
    other_headers = {"Authorization": f"Bearer {second.json()['access_token']}"}
    assert client.get(f"/customers/{created.json()['id']}", headers=other_headers).status_code == 404


def test_job_cannot_use_another_users_customer(account):
    client = account["client"]
    created = client.post("/customers", headers=account["headers"], json={"name": "Private Customer"})
    second = client.post("/auth/register", json={
        "email": "other2@example.com", "password": "another-long-password-456",
    })
    other_headers = {"Authorization": f"Bearer {second.json()['access_token']}"}
    response = client.post("/jobs", headers=other_headers, json={
        "customer_id": created.json()["id"], "title": "Unauthorized job", "trade_type": "Plumbing",
    })
    assert response.status_code == 404


def test_login_rate_limit_returns_429_and_retry_after(client, monkeypatch):
    fake = enable_fake_redis(monkeypatch)
    payload = {"email": "missing@example.com", "password": "wrong-password"}
    responses = [client.post("/auth/login", json=payload) for _ in range(6)]
    assert [response.status_code for response in responses] == [401] * 5 + [429]
    assert responses[-1].headers["Retry-After"] == "900"
    assert all("203.0.113.1" not in key for key in fake.counts)


def test_registration_rate_limit_returns_429(client, monkeypatch):
    enable_fake_redis(monkeypatch)
    responses = [client.post("/auth/register", json={
        "email": f"rate-{number}@example.com", "password": "a-long-test-password-123",
    }) for number in range(4)]
    assert [response.status_code for response in responses] == [201, 201, 201, 429]
    assert responses[-1].headers["Retry-After"] == "3600"


def test_production_rate_limiter_fails_closed_without_redis(client, monkeypatch):
    settings = rate_limit.get_settings()
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "redis_url", "")
    response = client.post("/auth/login", json={
        "email": "missing@example.com", "password": "wrong-password",
    })
    assert response.status_code == 503


def test_trusted_proxy_without_forwarded_header_uses_peer_ip(monkeypatch):
    monkeypatch.setattr(get_settings(), "trusted_proxy_cidrs", "10.0.0.0/8")
    assert rate_limit.client_ip(make_request("10.0.0.2")) == "10.0.0.2"


def test_trusted_proxy_chain_resolves_original_client(monkeypatch):
    monkeypatch.setattr(get_settings(), "trusted_proxy_cidrs", "10.0.0.0/8")
    assert rate_limit.client_ip(make_request("10.0.0.2", "203.0.113.8, 10.0.0.1")) == "203.0.113.8"


def test_untrusted_peer_cannot_spoof_forwarded_client_ip(monkeypatch):
    monkeypatch.setattr(get_settings(), "trusted_proxy_cidrs", "10.0.0.0/8")
    assert rate_limit.client_ip(make_request("198.51.100.4", "203.0.113.8")) == "198.51.100.4"


def test_malformed_forwarded_chain_is_rejected(monkeypatch):
    monkeypatch.setattr(get_settings(), "trusted_proxy_cidrs", "10.0.0.0/8")
    with pytest.raises(HTTPException) as error:
        rate_limit.client_ip(make_request("10.0.0.2", "not-an-ip"))
    assert error.value.status_code == 400


@pytest.mark.parametrize("token_kind", ["malformed", "expired", "invalid_signature"])
def test_invalid_jwt_is_rejected(client, token_kind):
    settings = get_settings()
    if token_kind == "malformed":
        token = "this-is-not-a-jwt"
    else:
        now = datetime.now(timezone.utc)
        payload = {"sub": "1", "iat": now - timedelta(hours=2), "exp": now - timedelta(hours=1)} if token_kind == "expired" else {"sub": "1", "iat": now, "exp": now + timedelta(minutes=5)}
        key = "wrong-signing-key" if token_kind == "invalid_signature" else settings.secret_key
        token = jwt.encode(payload, key, algorithm="HS256")
    response = client.get("/customers", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_production_redis_requires_tls_and_authentication():
    with pytest.raises(RuntimeError, match="rediss"):
        rate_limit._validate_production_redis_url("redis://:password@redis.internal:6379/0")


def test_production_redis_rejects_disabled_certificate_validation():
    with pytest.raises(RuntimeError, match="certificate verification"):
        rate_limit._validate_production_redis_url("rediss://:password@redis.internal:6379/0?ssl_cert_reqs=none")
