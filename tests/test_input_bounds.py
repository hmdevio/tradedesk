"""Input that PostgreSQL cannot store is rejected with 422 before the database.

Found by the 2026-11-26 security probe:
- An ID larger than a PostgreSQL INTEGER made the database driver raise (500).
- A NUL character (JSON escape \\u0000) was accepted in text fields; PostgreSQL
  refuses NUL in text, so on the real database the request would fail with a 500.
"""
import pytest

from app.schemas import MAX_RECORD_ID

TOO_BIG = 10 ** 40

RECORD_URLS = [
    ("GET", "/customers/{id}"),
    ("PATCH", "/customers/{id}"),
    ("DELETE", "/customers/{id}"),
    ("GET", "/customers/{id}/impact"),
    ("GET", "/jobs/{id}"),
    ("PATCH", "/jobs/{id}"),
    ("DELETE", "/jobs/{id}"),
    ("GET", "/jobs/{id}/impact"),
    ("GET", "/jobs/{id}/reports"),
    ("GET", "/jobs/{id}/tasks"),
    ("GET", "/jobs/{id}/worksheet"),
    ("GET", "/jobs/{id}/sketches"),
    ("GET", "/reports/{id}"),
    ("GET", "/reports/{id}/pdf"),
    ("POST", "/reports/{id}/approve"),
    ("PATCH", "/tasks/{id}"),
    ("DELETE", "/tasks/{id}"),
    ("GET", "/sketches/{id}/image"),
    ("DELETE", "/sketches/{id}"),
]


@pytest.mark.parametrize("record_id", [TOO_BIG, MAX_RECORD_ID + 1, 0, -1])
@pytest.mark.parametrize("method,url", RECORD_URLS, ids=[f"{m} {u}" for m, u in RECORD_URLS])
def test_out_of_range_ids_in_urls_are_rejected(account, method, url, record_id):
    client, headers = account["client"], account["headers"]
    response = client.request(method, url.format(id=record_id), headers=headers, json={})
    assert response.status_code == 422


def test_largest_valid_id_is_simply_not_found(account):
    client, headers = account["client"], account["headers"]
    assert client.get(f"/customers/{MAX_RECORD_ID}", headers=headers).status_code == 404


@pytest.mark.parametrize("customer_id", [TOO_BIG, MAX_RECORD_ID + 1])
def test_out_of_range_customer_id_when_creating_a_job(account, customer_id):
    client, headers = account["client"], account["headers"]
    response = client.post("/jobs", headers=headers,
                           json={"customer_id": customer_id, "title": "Panel upgrade", "trade_type": "Electrical"})
    assert response.status_code == 422


@pytest.mark.parametrize("url", ["/customers", "/jobs"])
def test_out_of_range_list_offset(account, url):
    client, headers = account["client"], account["headers"]
    assert client.get(f"{url}?offset={TOO_BIG}", headers=headers).status_code == 422
    assert client.get(f"{url}?offset={MAX_RECORD_ID}", headers=headers).status_code == 200


JSON = {"Content-Type": "application/json"}


@pytest.mark.parametrize("raw", [
    b'{"name": "nul \\u0000 inside"}',
    b'{"name": "Dana", "address": "nul \\u0000 inside"}',
    b'{"name": "Dana", "phone": "\\u0000"}',
], ids=["name", "address", "phone"])
def test_nul_characters_in_text_are_rejected(account, raw):
    client, headers = account["client"], account["headers"]
    response = client.post("/customers", headers={**headers, **JSON}, content=raw)
    assert response.status_code == 422
    assert response.json()["detail"] == "Text cannot contain NUL characters."
    assert client.get("/customers", headers=headers).json() == []


def test_nul_characters_are_rejected_on_updates_too(account):
    client, headers = account["client"], account["headers"]
    customer = client.post("/customers", headers=headers, json={"name": "Dana"}).json()
    response = client.patch(f"/customers/{customer['id']}", headers={**headers, **JSON},
                            content=b'{"name": "Da\\u0000na"}')
    assert response.status_code == 422


def test_typing_backslash_u0000_as_text_is_still_allowed(account):
    client, headers = account["client"], account["headers"]
    response = client.post("/customers", headers=headers, json={"name": "Note: \\u0000 is fine"})
    assert response.status_code == 201
    assert response.json()["name"] == "Note: \\u0000 is fine"
