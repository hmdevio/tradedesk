"""Authentication, validation, and ownership tests."""

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
