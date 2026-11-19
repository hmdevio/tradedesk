"""Editing, deleting and status changes for customers, jobs and tasks (Sprint 1, U5)."""
PASSWORD = "a-long-test-password-123"


def setup_job(client, headers, name="Dana Ortiz", title="Water heater"):
    customer = client.post("/customers", headers=headers, json={
        "name": name, "email": "dana@example.com", "phone": "555-0100",
    }).json()
    job = client.post("/jobs", headers=headers, json={
        "customer_id": customer["id"], "title": title, "trade_type": "Plumbing",
    }).json()
    return customer, job


def draft(client, headers, job_id):
    return client.post(
        f"/jobs/{job_id}/reports/draft", headers=headers, json={"notes": "Done."}
    ).json()


def test_customer_impact_counts_what_a_delete_removes(account):
    client, headers = account["client"], account["headers"]
    customer, job = setup_job(client, headers)
    client.post("/jobs", headers=headers, json={
        "customer_id": customer["id"], "title": "Second job", "trade_type": "Plumbing",
    })
    draft(client, headers, job["id"])
    client.post(f"/jobs/{job['id']}/tasks", headers=headers, json={"title": "Call back"})

    impact = client.get(f"/customers/{customer['id']}/impact", headers=headers).json()
    assert impact == {
        "jobs": 2, "reports": 1, "approved_reports": 0, "tasks": 1, "sketches": 0,
    }


def test_customer_with_only_drafts_can_be_deleted(account):
    client, headers = account["client"], account["headers"]
    customer, job = setup_job(client, headers)
    draft(client, headers, job["id"])
    assert client.delete(f"/customers/{customer['id']}", headers=headers).status_code == 204
    assert client.get(f"/jobs/{job['id']}", headers=headers).status_code == 404


def test_customer_with_an_approved_report_cannot_be_deleted(account):
    client, headers = account["client"], account["headers"]
    customer, job = setup_job(client, headers)
    report = draft(client, headers, job["id"])
    client.post(f"/reports/{report['id']}/approve", headers=headers)

    impact = client.get(f"/customers/{customer['id']}/impact", headers=headers).json()
    assert impact["approved_reports"] == 1

    response = client.delete(f"/customers/{customer['id']}", headers=headers)
    assert response.status_code == 409
    assert "approved reports" in response.json()["detail"]
    # Nothing was removed.
    assert client.get(f"/reports/{report['id']}", headers=headers).status_code == 200


def test_job_with_an_approved_report_cannot_be_deleted(account):
    client, headers = account["client"], account["headers"]
    _, job = setup_job(client, headers)
    report = draft(client, headers, job["id"])
    client.post(f"/reports/{report['id']}/approve", headers=headers)

    assert client.get(f"/jobs/{job['id']}/impact", headers=headers).json()["approved_reports"] == 1
    response = client.delete(f"/jobs/{job['id']}", headers=headers)
    assert response.status_code == 409
    assert "Completed or Cancelled" in response.json()["detail"]


def test_job_without_approved_reports_can_be_deleted(account):
    client, headers = account["client"], account["headers"]
    _, job = setup_job(client, headers)
    client.post(f"/jobs/{job['id']}/tasks", headers=headers, json={"title": "Call back"})
    impact = client.get(f"/jobs/{job['id']}/impact", headers=headers).json()
    assert impact["jobs"] == 1 and impact["tasks"] == 1
    assert client.delete(f"/jobs/{job['id']}", headers=headers).status_code == 204


def test_impact_is_owner_only(account, register_verified_user):
    client, headers = account["client"], account["headers"]
    customer, job = setup_job(client, headers)
    intruder = register_verified_user("intruder@example.com", PASSWORD)["headers"]
    assert client.get(f"/customers/{customer['id']}/impact", headers=intruder).status_code == 404
    assert client.get(f"/jobs/{job['id']}/impact", headers=intruder).status_code == 404


def test_customer_edit_can_clear_optional_fields(account):
    client, headers = account["client"], account["headers"]
    customer, _ = setup_job(client, headers)
    updated = client.patch(f"/customers/{customer['id']}", headers=headers, json={
        "name": "Dana O.", "email": None, "phone": "", "address": "12 Elm St",
    })
    assert updated.status_code == 200, updated.text
    body = updated.json()
    assert body["name"] == "Dana O."
    assert body["email"] is None
    assert body["address"] == "12 Elm St"


def test_job_moves_through_every_status(account):
    client, headers = account["client"], account["headers"]
    _, job = setup_job(client, headers)
    for status in ("In Progress", "Completed", "Cancelled", "New"):
        response = client.patch(f"/jobs/{job['id']}", headers=headers, json={"status": status})
        assert response.status_code == 200
        assert response.json()["status"] == status
    bad = client.patch(f"/jobs/{job['id']}", headers=headers, json={"status": "Done"})
    assert bad.status_code == 422


def test_task_can_be_reopened_and_its_due_date_cleared(account):
    client, headers = account["client"], account["headers"]
    _, job = setup_job(client, headers)
    task = client.post(f"/jobs/{job['id']}/tasks", headers=headers, json={
        "title": "Call back", "due_at": "2026-12-01T15:00:00Z",
    }).json()
    done = client.patch(f"/tasks/{task['id']}", headers=headers, json={"status": "Completed"}).json()
    assert done["status"] == "Completed"
    reopened = client.patch(f"/tasks/{task['id']}", headers=headers, json={
        "status": "Pending", "due_at": None, "title": "Call back Friday",
    }).json()
    assert reopened["status"] == "Pending"
    assert reopened["due_at"] is None
    assert reopened["title"] == "Call back Friday"


def test_task_times_are_sent_with_a_utc_offset(account):
    client, headers = account["client"], account["headers"]
    _, job = setup_job(client, headers)
    task = client.post(f"/jobs/{job['id']}/tasks", headers=headers, json={
        "title": "Call back", "due_at": "2026-01-05T15:00:00Z",
    }).json()
    listed = client.get(f"/jobs/{job['id']}/tasks", headers=headers).json()[0]
    for value in (task["due_at"], listed["due_at"], listed["created_at"]):
        assert value.endswith(("Z", "+00:00")), value
    assert listed["due_at"].startswith("2026-01-05T15:00:00")


def test_favicon_is_served(client):
    for path in ("/favicon.ico", "/static/favicon.svg"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("image/svg+xml")
