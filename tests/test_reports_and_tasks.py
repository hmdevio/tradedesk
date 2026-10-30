"""Report workflow, PDF approval gate, and task ownership tests."""
def setup_job(client, headers):
    customer = client.post("/customers", headers=headers, json={"name": "Sample Customer"})
    assert customer.status_code == 201
    job = client.post("/jobs", headers=headers, json={
        "customer_id": customer.json()["id"],
        "title": "Faucet repair",
        "trade_type": "Plumbing",
        "notes": "Replaced cartridge and tested faucet.",
    })
    assert job.status_code == 201
    return job.json()["id"]


def test_report_starts_as_draft_and_pdf_is_blocked(account):
    client, headers = account["client"], account["headers"]
    job_id = setup_job(client, headers)
    draft = client.post(f"/jobs/{job_id}/reports/draft", headers=headers, json={
        "notes": "Replaced faucet cartridge. Tested faucet."
    })
    assert draft.status_code == 201
    report = draft.json()
    assert report["status"] == "Draft"
    assert "Not separately specified" in report["generated_content"]

    blocked = client.get(f"/reports/{report['id']}/pdf", headers=headers)
    assert blocked.status_code == 409


def test_report_approval_allows_pdf_export(account):
    client, headers = account["client"], account["headers"]
    job_id = setup_job(client, headers)
    draft = client.post(f"/jobs/{job_id}/reports/draft", headers=headers, json={
        "notes": "Replaced faucet cartridge."
    }).json()
    edited = client.patch(f"/reports/{draft['id']}", headers=headers, json={
        "generated_content": '{"work_performed":"Replaced faucet cartridge."}'
    })
    assert edited.status_code == 200
    approved = client.post(f"/reports/{draft['id']}/approve", headers=headers)
    assert approved.status_code == 200
    assert approved.json()["status"] == "Approved"
    pdf = client.get(f"/reports/{draft['id']}/pdf", headers=headers)
    assert pdf.status_code == 200
    assert pdf.headers["content-type"].startswith("application/pdf")
    assert pdf.content.startswith(b"%PDF")


def test_approved_report_cannot_be_edited(account):
    client, headers = account["client"], account["headers"]
    job_id = setup_job(client, headers)
    report = client.post(f"/jobs/{job_id}/reports/draft", headers=headers, json={
        "notes": "Checked equipment."
    }).json()
    client.post(f"/reports/{report['id']}/approve", headers=headers)
    edited = client.patch(f"/reports/{report['id']}", headers=headers, json={
        "generated_content": "Changed after approval"
    })
    assert edited.status_code == 409


def test_task_lifecycle(account):
    client, headers = account["client"], account["headers"]
    job_id = setup_job(client, headers)
    task = client.post(f"/jobs/{job_id}/tasks", headers=headers, json={
        "title": "Call customer next week"
    })
    assert task.status_code == 201
    assert task.json()["status"] == "Pending"
    updated = client.patch(f"/tasks/{task.json()['id']}", headers=headers, json={
        "status": "Completed"
    })
    assert updated.status_code == 200
    assert updated.json()["status"] == "Completed"


def test_task_cannot_be_seen_or_changed_by_another_user(account):
    client, headers = account["client"], account["headers"]
    job_id = setup_job(client, headers)
    task = client.post(f"/jobs/{job_id}/tasks", headers=headers, json={"title": "Private follow-up"}).json()
    second = client.post("/auth/register", json={
        "email": "third@example.com",
        "password": "another-long-password-789",
    })
    other_headers = {"Authorization": f"Bearer {second.json()['access_token']}"}
    response = client.patch(f"/tasks/{task['id']}", headers=other_headers, json={"status": "Completed"})
    assert response.status_code == 404
