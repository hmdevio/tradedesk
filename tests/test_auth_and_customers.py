"""Authentication, validation, ownership, and rate-limit tests."""
import app.rate_limit as rate_limit


class FakeRedis:
    """Small deterministic Redis stand-in for endpoint rate-limit tests."""
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


def test_protected_endpoint_requires_auth(client):
    response = client.get("/customers")
    assert response.status_code == 401


def test_register_and_login(account):
    client = account["client"]
    response = client.post("/auth/login", json={
        "email": "owner@example.com",
        "password": "a-long-test-password-123",
    })
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"


def test_short_password_rejected(client):
    response = client.post("/auth/register", json={
        "email": "short@example.com",
        "password": "short",
    })
    assert response.status_code == 422


def test_customer_owner_isolation(account):
    client = account["client"]
    own_headers = account["headers"]
    created = client.post("/customers", headers=own_headers, json={"name": "Test Customer"})
    assert created.status_code == 201
    customer_id = created.json()["id"]

    second = client.post("/auth/register", json={
        "email": "other@example.com",
        "password": "another-long-password-123",
    })
    other_headers = {"Authorization": f"Bearer {second.json()['access_token']}"}
    response = client.get(f"/customers/{customer_id}", headers=other_headers)
    assert response.status_code == 404


def test_job_cannot_use_another_users_customer(account):
    client = account["client"]
    created = client.post("/customers", headers=account["headers"], json={"name": "Private Customer"})
    second = client.post("/auth/register", json={
        "email": "other2@example.com",
        "password": "another-long-password-456",
    })
    other_headers = {"Authorization": f"Bearer {second.json()['access_token']}"}
    response = client.post("/jobs", headers=other_headers, json={
        "customer_id": created.json()["id"],
        "title": "Unauthorized job",
        "trade_type": "Plumbing",
    })
    assert response.status_code == 404


def test_login_rate_limit_returns_429_and_retry_after(client, monkeypatch):
    enable_fake_redis(monkeypatch)
    payload = {"email": "missing@example.com", "password": "wrong-password"}
    responses = [client.post("/auth/login", json=payload) for _ in range(6)]
    assert [response.status_code for response in responses] == [401] * 5 + [429]
    assert responses[-1].headers["Retry-After"] == "900"


def test_registration_rate_limit_returns_429(client, monkeypatch):
    enable_fake_redis(monkeypatch)
    responses = [
        client.post("/auth/register", json={
            "email": f"rate-{number}@example.com",
            "password": "a-long-test-password-123",
        })
        for number in range(4)
    ]
    assert [response.status_code for response in responses] == [201, 201, 201, 429]
    assert responses[-1].headers["Retry-After"] == "3600"


def test_production_rate_limiter_fails_closed_without_redis(client, monkeypatch):
    settings = rate_limit.get_settings()
    monkeypatch.setattr(settings, "environment", "production")
    monkeypatch.setattr(settings, "redis_url", "")
    response = client.post("/auth/login", json={
        "email": "missing@example.com",
        "password": "wrong-password",
    })
    assert response.status_code == 503
