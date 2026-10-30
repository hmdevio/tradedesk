"""Test fixtures use an isolated temporary SQLite database."""
import os
import tempfile
import pytest

# Must be set before importing app modules so their engine uses the test database.
_fd, _path = tempfile.mkstemp(prefix="tradedesk-test-", suffix=".db")
os.close(_fd)
os.environ["DATABASE_URL"] = f"sqlite:///{_path}"
os.environ["SECRET_KEY"] = "test-only-secret-key-that-is-not-for-production"
os.environ["ENVIRONMENT"] = "test"

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
def account(client):
    response = client.post("/auth/register", json={
        "email": "owner@example.com",
        "password": "a-long-test-password-123",
    })
    assert response.status_code == 201
    token = response.json()["access_token"]
    return {"client": client, "headers": {"Authorization": f"Bearer {token}"}}
