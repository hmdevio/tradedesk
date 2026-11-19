"""Business profile printed on PDF reports (Sprint 1)."""
import base64
import io

from PIL import Image
from pypdf import PdfReader


PASSWORD = "a-long-test-password-123"
PROFILE = {
    "business_name": "Ortiz Electric LLC",
    "phone": "555-0199",
    "email": "Office@OrtizElectric.example",
    "address": "400 Main St, Hartford CT",
    "license_number": "E1-123456",
}


def logo_url(size=(1200, 400)):
    image = Image.new("RGB", size, "white")
    for x in range(size[0]):
        image.putpixel((x, size[1] // 2), (200, 30, 30))
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode()


def pdf_text(content):
    return "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(content)).pages)


def approved_pdf(client, headers):
    customer = client.post("/customers", headers=headers, json={"name": "Dana Smith"}).json()
    job = client.post("/jobs", headers=headers, json={
        "customer_id": customer["id"], "title": "Panel upgrade", "trade_type": "Electrical",
    }).json()
    report = client.post(f"/jobs/{job['id']}/reports/draft", headers=headers,
                         json={"notes": "Replaced the panel."}).json()
    client.post(f"/reports/{report['id']}/approve", headers=headers)
    return report["id"]


def test_profile_is_empty_until_saved(account):
    response = account["client"].get("/profile", headers=account["headers"])
    assert response.status_code == 200
    assert response.json() is None


def test_profile_saves_and_clears_fields(account):
    client, headers = account["client"], account["headers"]
    saved = client.put("/profile", headers=headers, json=PROFILE).json()
    assert saved["business_name"] == "Ortiz Electric LLC"
    assert saved["email"] == "office@ortizelectric.example"
    assert saved["has_logo"] is False
    cleared = client.put("/profile", headers=headers, json={
        "business_name": "Ortiz Electric", "phone": "", "license_number": "",
    }).json()
    assert cleared["phone"] is None and cleared["license_number"] is None


def test_profile_validation(account):
    client, headers = account["client"], account["headers"]
    assert client.put("/profile", headers=headers, json={"business_name": "  "}).status_code == 422
    assert client.put("/profile", headers=headers,
                      json={"business_name": "X", "email": "nope"}).status_code == 422
    assert client.put("/profile", headers=headers,
                      json={"business_name": "X" * 121}).status_code == 422


def test_profile_requires_sign_in(client):
    assert client.get("/profile").status_code == 401
    assert client.put("/profile", json=PROFILE).status_code == 401


def test_logo_needs_a_profile_first(account):
    response = account["client"].put("/profile/logo", headers=account["headers"],
                                     json={"image": logo_url()})
    assert response.status_code == 409


def test_logo_upload_is_resized_served_and_removable(account):
    client, headers = account["client"], account["headers"]
    client.put("/profile", headers=headers, json=PROFILE)
    saved = client.put("/profile/logo", headers=headers, json={"image": logo_url()})
    assert saved.status_code == 200 and saved.json()["has_logo"] is True
    stored = client.get("/profile/logo", headers=headers)
    assert stored.status_code == 200
    assert max(Image.open(io.BytesIO(stored.content)).size) == 600
    assert client.delete("/profile/logo", headers=headers).status_code == 204
    assert client.get("/profile/logo", headers=headers).status_code == 404


def test_logo_rejects_non_images(account):
    client, headers = account["client"], account["headers"]
    client.put("/profile", headers=headers, json=PROFILE)
    bad = "data:image/png;base64," + base64.b64encode(b"<svg/>").decode()
    assert client.put("/profile/logo", headers=headers, json={"image": bad}).status_code == 422


def test_profiles_are_per_account(account, register_verified_user):
    client, headers = account["client"], account["headers"]
    client.put("/profile", headers=headers, json=PROFILE)
    client.put("/profile/logo", headers=headers, json={"image": logo_url()})
    other = register_verified_user("other@example.com", PASSWORD)["headers"]
    assert client.get("/profile", headers=other).json() is None
    assert client.get("/profile/logo", headers=other).status_code == 404


def test_pdf_prints_the_business_header(account):
    client, headers = account["client"], account["headers"]
    client.put("/profile", headers=headers, json=PROFILE)
    client.put("/profile/logo", headers=headers, json={"image": logo_url()})
    report_id = approved_pdf(client, headers)

    pdf = client.get(f"/reports/{report_id}/pdf", headers=headers).content
    text = pdf_text(pdf)
    assert "Ortiz Electric LLC" in text
    assert "License #E1-123456" in text
    assert "555-0199" in text and "400 Main St" in text
    assert "Prepared by: Ortiz Electric LLC" in text
    assert "owner@example.com" not in text
    images = [img for page in PdfReader(io.BytesIO(pdf)).pages for img in page.images]
    assert len(images) == 1  # the logo


def test_approved_pdf_keeps_the_business_details_from_approval(account):
    client, headers = account["client"], account["headers"]
    client.put("/profile", headers=headers, json=PROFILE)
    report_id = approved_pdf(client, headers)
    client.put("/profile", headers=headers, json={"business_name": "New Name Inc"})
    text = pdf_text(client.get(f"/reports/{report_id}/pdf", headers=headers).content)
    assert "Ortiz Electric LLC" in text and "New Name Inc" not in text


def test_reports_without_a_profile_keep_the_account_email(account):
    client, headers = account["client"], account["headers"]
    report_id = approved_pdf(client, headers)
    text = pdf_text(client.get(f"/reports/{report_id}/pdf", headers=headers).content)
    assert "Prepared by: owner@example.com" in text
