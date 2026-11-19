"""Regression tests for the Phase 1 audit fixes (2026-11-18 audit).

S2 security headers, S3 partial-update validation, S4 unverified
re-registration, U1/U6 report content and PDF, U2 report history,
U3 session refresh, U4 password reset.
"""
from datetime import datetime, timedelta, timezone
import io
import json

import pytest
from pypdf import PdfReader
from sqlalchemy import update

from app.database import SessionLocal
from app.models import PasswordResetToken


PASSWORD = "a-long-test-password-123"


@pytest.fixture()
def reset_emails(monkeypatch):
    """Capture password reset emails without SMTP."""
    messages = []

    def fake_send(recipient: str, token: str) -> None:
        messages.append({"recipient": recipient, "token": token})

    monkeypatch.setattr("app.main.send_password_reset_email", fake_send)
    return messages


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def make_job(client, headers, **customer_fields):
    customer = client.post(
        "/customers",
        headers=headers,
        json={"name": "Dana Smith", **customer_fields},
    ).json()
    job = client.post("/jobs", headers=headers, json={
        "customer_id": customer["id"],
        "title": "Kitchen leak",
        "trade_type": "Plumbing",
    }).json()
    return customer, job


def pdf_text(content: bytes) -> str:
    reader = PdfReader(io.BytesIO(content))
    return "\n".join(page.extract_text() for page in reader.pages)


# S2: security headers


def test_security_headers_on_page_and_api(account):
    client, headers = account["client"], account["headers"]

    page = client.get("/")
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    assert "script-src 'self'" in page.headers["content-security-policy"]
    assert page.headers["x-frame-options"] == "DENY"
    assert page.headers["x-content-type-options"] == "nosniff"
    assert page.headers["referrer-policy"] == "no-referrer"

    api = client.get("/customers", headers=headers)
    assert api.headers["cache-control"] == "no-store"
    assert "content-security-policy" in api.headers

    # HSTS is only sent in production.
    assert "strict-transport-security" not in api.headers


def test_docs_are_excluded_from_csp(client):
    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "content-security-policy" not in docs.headers
    assert docs.headers["x-frame-options"] == "DENY"


# S3: partial updates


def test_explicit_nulls_on_required_fields_are_rejected(account):
    client, headers = account["client"], account["headers"]
    customer, job = make_job(client, headers)
    task = client.post(
        f"/jobs/{job['id']}/tasks", headers=headers, json={"title": "Call"}
    ).json()

    cases = [
        (f"/customers/{customer['id']}", {"name": None}),
        (f"/jobs/{job['id']}", {"title": None}),
        (f"/jobs/{job['id']}", {"trade_type": None}),
        (f"/jobs/{job['id']}", {"status": None}),
        (f"/tasks/{task['id']}", {"title": None}),
        (f"/tasks/{task['id']}", {"status": None}),
    ]
    for path, body in cases:
        response = client.patch(path, headers=headers, json=body)
        assert response.status_code == 422, (path, body, response.text)

    # Optional fields can still be cleared.
    cleared = client.patch(
        f"/customers/{customer['id']}", headers=headers, json={"phone": None}
    )
    assert cleared.status_code == 200
    cleared_task = client.patch(
        f"/tasks/{task['id']}", headers=headers, json={"due_at": None}
    )
    assert cleared_task.status_code == 200


def test_renaming_to_duplicate_title_returns_409(account):
    client, headers = account["client"], account["headers"]
    customer, job = make_job(client, headers)
    other = client.post("/jobs", headers=headers, json={
        "customer_id": customer["id"],
        "title": "Water heater",
        "trade_type": "Plumbing",
    }).json()

    renamed = client.patch(
        f"/jobs/{other['id']}", headers=headers, json={"title": " kitchen LEAK "}
    )
    assert renamed.status_code == 409

    first = client.post(
        f"/jobs/{job['id']}/tasks", headers=headers, json={"title": "Call"}
    ).json()
    client.post(f"/jobs/{job['id']}/tasks", headers=headers, json={"title": "Bill"})
    task_renamed = client.patch(
        f"/tasks/{first['id']}", headers=headers, json={"title": "bill"}
    )
    assert task_renamed.status_code == 409

    # Renaming a record to its own title (different case) is allowed.
    same = client.patch(
        f"/jobs/{job['id']}", headers=headers, json={"title": "Kitchen Leak"}
    )
    assert same.status_code == 200


def test_field_lengths_match_database_columns(account):
    client, headers = account["client"], account["headers"]

    too_long_name = client.post(
        "/customers", headers=headers, json={"name": "x" * 121}
    )
    assert too_long_name.status_code == 422
    customer = client.post(
        "/customers", headers=headers, json={"name": "x" * 120}
    )
    assert customer.status_code == 201

    too_long_title = client.post("/jobs", headers=headers, json={
        "customer_id": customer.json()["id"],
        "title": "t" * 161,
        "trade_type": "HVAC",
    })
    assert too_long_title.status_code == 422


# S4: re-registration tests moved to tests/test_phase2a_fixes.py, where the
# behavior changed (re-audit finding N1).


# U3: session refresh


def test_refresh_issues_new_token_and_revokes_old(account):
    client, headers = account["client"], account["headers"]

    refreshed = client.post("/auth/refresh", headers=headers)
    assert refreshed.status_code == 200
    body = refreshed.json()
    assert body["expires_in_seconds"] > 0

    assert client.get("/customers", headers=headers).status_code == 401
    assert client.get(
        "/customers", headers=auth(body["access_token"])
    ).status_code == 200


def test_refresh_requires_a_live_session(account):
    client, headers = account["client"], account["headers"]
    client.post("/auth/logout", headers=headers)
    assert client.post("/auth/refresh", headers=headers).status_code == 401
    assert client.post("/auth/refresh").status_code == 401


# U4: password reset


def test_forgot_password_response_does_not_reveal_accounts(
    account, reset_emails
):
    client = account["client"]
    known = client.post(
        "/auth/forgot-password", json={"email": "Owner@Example.com "}
    )
    unknown = client.post(
        "/auth/forgot-password", json={"email": "nobody@example.com"}
    )
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json()
    assert [m["recipient"] for m in reset_emails] == ["owner@example.com"]


def test_password_reset_sets_password_and_ends_sessions(account, reset_emails):
    client, headers = account["client"], account["headers"]
    client.post("/auth/forgot-password", json={"email": "owner@example.com"})
    token = reset_emails[-1]["token"]

    new_password = "brand-new-password-456"
    reset = client.post(
        "/auth/reset-password", json={"token": token, "new_password": new_password}
    )
    assert reset.status_code == 200

    # Existing sessions are revoked.
    assert client.get("/customers", headers=headers).status_code == 401

    old = client.post(
        "/auth/login", json={"email": "owner@example.com", "password": PASSWORD}
    )
    assert old.status_code == 401
    new = client.post(
        "/auth/login", json={"email": "owner@example.com", "password": new_password}
    )
    assert new.status_code == 200

    # Single use.
    again = client.post(
        "/auth/reset-password", json={"token": token, "new_password": "another-password-789"}
    )
    assert again.status_code == 400


def test_new_reset_request_invalidates_previous_link(account, reset_emails):
    client = account["client"]
    client.post("/auth/forgot-password", json={"email": "owner@example.com"})
    first = reset_emails[-1]["token"]
    client.post("/auth/forgot-password", json={"email": "owner@example.com"})
    second = reset_emails[-1]["token"]

    stale = client.post(
        "/auth/reset-password", json={"token": first, "new_password": "brand-new-password-456"}
    )
    assert stale.status_code == 400
    fresh = client.post(
        "/auth/reset-password", json={"token": second, "new_password": "brand-new-password-456"}
    )
    assert fresh.status_code == 200


def test_expired_reset_token_is_rejected(account, reset_emails):
    client = account["client"]
    client.post("/auth/forgot-password", json={"email": "owner@example.com"})
    token = reset_emails[-1]["token"]

    with SessionLocal() as db:
        db.execute(
            update(PasswordResetToken).values(
                expires_at=datetime.now(timezone.utc) - timedelta(minutes=1)
            )
        )
        db.commit()

    expired = client.post(
        "/auth/reset-password", json={"token": token, "new_password": "brand-new-password-456"}
    )
    assert expired.status_code == 400


def test_reset_rejects_short_password(account, reset_emails):
    client = account["client"]
    client.post("/auth/forgot-password", json={"email": "owner@example.com"})
    short = client.post(
        "/auth/reset-password",
        json={"token": reset_emails[-1]["token"], "new_password": "short"},
    )
    assert short.status_code == 422


def test_reset_verifies_unverified_account_and_voids_verification_links(
    client, verification_emails, reset_emails
):
    """Closes S4 completely: the email owner can always take the account back."""
    email = "late@example.com"
    client.post("/auth/register", json={"email": email, "password": "attacker-chosen-password"})
    verification_token = verification_emails[-1]["token"]

    client.post("/auth/forgot-password", json={"email": email})
    reset = client.post(
        "/auth/reset-password",
        json={"token": reset_emails[-1]["token"], "new_password": "owners-real-password-1"},
    )
    assert reset.status_code == 200

    login = client.post(
        "/auth/login", json={"email": email, "password": "owners-real-password-1"}
    )
    assert login.status_code == 200
    stale = client.post(
        "/auth/verify-email",
        json={"token": verification_token, "password": "owners-real-password-1"},
    )
    assert stale.status_code == 400


def test_reset_email_failure_still_returns_generic_response(
    account, monkeypatch
):
    def fail(recipient, token):
        raise RuntimeError("smtp down")

    monkeypatch.setattr("app.main.send_password_reset_email", fail)
    response = account["client"].post(
        "/auth/forgot-password", json={"email": "owner@example.com"}
    )
    assert response.status_code == 200


# U1 / U2: report content and history


def test_report_history_lists_and_reopens_reports(account, register_verified_user):
    client, headers = account["client"], account["headers"]
    _, job = make_job(client, headers)

    first = client.post(
        f"/jobs/{job['id']}/reports/draft", headers=headers, json={"notes": "First visit."}
    ).json()
    second = client.post(
        f"/jobs/{job['id']}/reports/draft", headers=headers, json={"notes": "Second visit."}
    ).json()
    client.post(f"/reports/{first['id']}/approve", headers=headers)

    history = client.get(f"/jobs/{job['id']}/reports", headers=headers)
    assert history.status_code == 200
    assert [(r["id"], r["status"]) for r in history.json()] == [
        (second["id"], "Draft"),
        (first["id"], "Approved"),
    ]

    reopened = client.get(f"/reports/{first['id']}", headers=headers)
    assert reopened.status_code == 200
    assert reopened.json()["status"] == "Approved"

    other = register_verified_user("other@example.com", "other-account-password")
    assert client.get(
        f"/jobs/{job['id']}/reports", headers=other["headers"]
    ).status_code == 404
    assert client.get(
        f"/reports/{first['id']}", headers=other["headers"]
    ).status_code == 404


@pytest.mark.parametrize("content", [
    "plain text is not a section object",
    json.dumps(["work_performed"]),
    json.dumps({"work_performed": 5}),
    json.dumps({"surprise": "unknown key"}),
    json.dumps({"work_performed": "x" * 5001}),
])
def test_report_edits_must_be_valid_sections(account, content):
    client, headers = account["client"], account["headers"]
    _, job = make_job(client, headers)
    report = client.post(
        f"/jobs/{job['id']}/reports/draft", headers=headers, json={"notes": "Visit."}
    ).json()
    response = client.patch(
        f"/reports/{report['id']}", headers=headers, json={"generated_content": content}
    )
    assert response.status_code == 422


def test_pdf_is_client_ready_and_escapes_markup(account):
    client, headers = account["client"], account["headers"]
    _, job = make_job(
        client, headers,
        address="12 Elm St, Springfield",
        phone="555-0100",
        email="dana@example.com",
    )
    report = client.post(
        f"/jobs/{job['id']}/reports/draft", headers=headers,
        json={"notes": "Replaced P-trap."},
    ).json()
    long_word = "A" * 400
    edited = client.patch(f"/reports/{report['id']}", headers=headers, json={
        "generated_content": json.dumps({
            "work_performed": f"Replaced P-trap. {long_word} Température OK ✅",
            "findings_observations": "Corroded <img src='/etc/passwd'/> trap & seal.",
            "recommendations": "",
            "suggested_follow_up": "Confirm follow-up needs with the customer if applicable.",
            "source_note": "internal reviewer note",
        })
    })
    assert edited.status_code == 200
    client.post(f"/reports/{report['id']}/approve", headers=headers)

    pdf = client.get(f"/reports/{report['id']}/pdf", headers=headers)
    assert pdf.status_code == 200
    text = pdf_text(pdf.content)
    flat = text.replace("\n", "")

    # Header data a customer expects.
    for expected in ("Service Report", f"Report #{report['id']}", "Dana Smith",
                     "12 Elm St, Springfield", "555-0100", "Kitchen leak",
                     "Plumbing", "owner@example.com", "Customer signature"):
        assert expected in text, expected

    # Sections are readable text, not JSON.
    assert "Work performed" in text
    assert "Findings and observations" in text
    assert "work_performed" not in text and "{" not in text

    # Blank sections and untouched placeholders are left out; internal
    # reviewer notes are never printed.
    assert "Recommendations" not in text
    assert "Suggested follow-up" not in text
    assert "internal reviewer note" not in text

    # Long words wrap instead of being cut off; Unicode survives.
    assert long_word in flat
    assert "Température OK" in text

    # Markup in user text is printed literally, never interpreted.
    assert "<img src='/etc/passwd'/>" in text
    assert "trap & seal" in text


def test_legacy_plain_text_report_still_exports(account):
    """Reports edited before this change may hold plain text."""
    client, headers = account["client"], account["headers"]
    _, job = make_job(client, headers)
    report = client.post(
        f"/jobs/{job['id']}/reports/draft", headers=headers, json={"notes": "Visit."}
    ).json()

    from app.models import ServiceReport
    with SessionLocal() as db:
        db.execute(
            update(ServiceReport)
            .where(ServiceReport.id == report["id"])
            .values(generated_content="Legacy free-text report body.")
        )
        db.commit()

    client.post(f"/reports/{report['id']}/approve", headers=headers)
    pdf = client.get(f"/reports/{report['id']}/pdf", headers=headers)
    assert pdf.status_code == 200
    assert "Legacy free-text report body." in pdf_text(pdf.content)
