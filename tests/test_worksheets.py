"""Trade worksheets and sketch uploads (Phase 2c)."""
import base64
import io
import json

import pytest
from PIL import Image
from pypdf import PdfReader

from app.worksheets import TRADES


PASSWORD = "a-long-test-password-123"

SAMPLE_VALUES = {
    "electrician": {
        "panel_location": "Garage main panel", "circuit": "Kitchen 20A",
        "breaker_amps": 20, "wire_gauge": "12 AWG", "voltage_reading": 121.5,
        "gfci_afci_tested": True, "permit_number": "E-2026-114",
    },
    "plumber": {
        "fixture_system": "Kitchen sink", "pipe_material": "PEX",
        "pressure_test_psi": 80, "leak_check": "Pass",
        "water_heater": "Rheem 50 gal", "shutoff_location": "Basement, north wall",
    },
    "hvac": {
        "system_type": "Heat pump", "equipment": "Carrier 25HCE4 / SN 123",
        "refrigerant_type": "R-410A", "refrigerant_charge": "8 lb 4 oz",
        "filter_size": "16x25x1", "filter_changed": True,
        "supply_temp_f": 56, "return_temp_f": 74, "static_pressure": 0.5,
    },
    "carpenter": {
        "area_room": "Back deck", "materials": "12 x 2x6 PT, 3 lb screws",
        "measurements": "12 ft x 16 ft", "fasteners_finish": "Deck screws, stain",
        "structural": True,
    },
    "welder": {
        "process": "MIG (GMAW)", "base_metal": "A36 steel", "thickness": "3/8 in",
        "filler": "ER70S-6", "position": "2G/2F horizontal",
        "joint_type": "Fillet / T", "inspection": "Visual - pass",
    },
    "mechanic": {
        "vin": "1hgcm82633a004352", "vehicle": "2003 Honda Accord",
        "mileage_hours": "182,400 mi", "complaint": "Grinding when braking",
        "diagnostic_codes": "None", "parts_replaced": "Front pads and rotors",
        "torque_fluid_notes": "Lug nuts 80 ft-lb",
    },
}


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def make_job(client, headers, title="Panel upgrade"):
    customer = client.post(
        "/customers", headers=headers, json={"name": "Dana Smith"}
    ).json()
    return client.post("/jobs", headers=headers, json={
        "customer_id": customer["id"], "title": title, "trade_type": "Electrical",
    }).json()


def data_url(image, fmt="PNG", **save_args):
    buffer = io.BytesIO()
    image.save(buffer, format=fmt, **save_args)
    mime = {"PNG": "png", "JPEG": "jpeg", "WEBP": "webp"}[fmt]
    return f"data:image/{mime};base64," + base64.b64encode(buffer.getvalue()).decode()


def drawing():
    """A simple black-on-white line drawing, like a plot sketch."""
    image = Image.new("RGB", (400, 300), "white")
    for x in range(50, 350):
        image.putpixel((x, 150), (0, 0, 0))
    return image


def pdf_text(content):
    return "\n".join(p.extract_text() for p in PdfReader(io.BytesIO(content)).pages)


# Templates and saving


def test_templates_cover_the_six_trades(account):
    response = account["client"].get("/worksheet-templates", headers=account["headers"])
    assert response.status_code == 200
    assert [t["label"] for t in response.json()] == [
        "Electrician", "Plumber", "HVAC technician", "Carpenter", "Welder",
        "Automotive & diesel mechanic",
    ]


def test_templates_require_sign_in(client):
    assert client.get("/worksheet-templates").status_code == 401


def test_job_has_no_worksheet_until_saved(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    response = client.get(f"/jobs/{job['id']}/worksheet", headers=headers)
    assert response.status_code == 200
    assert response.json() is None


@pytest.mark.parametrize("trade", list(TRADES))
def test_each_trade_saves_and_reads_back(account, trade):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    saved = client.put(f"/jobs/{job['id']}/worksheet", headers=headers, json={
        "trade": trade, "values": SAMPLE_VALUES[trade], "notes": "  All good.  ",
    })
    assert saved.status_code == 200, saved.text
    body = client.get(f"/jobs/{job['id']}/worksheet", headers=headers).json()
    assert body["trade"] == trade
    assert body["trade_label"] == TRADES[trade]["label"]
    assert body["notes"] == "All good."
    assert set(body["values"]) == set(SAMPLE_VALUES[trade])


def test_vin_is_normalized_to_upper_case(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    client.put(f"/jobs/{job['id']}/worksheet", headers=headers, json={
        "trade": "mechanic", "values": {"vin": "1hgcm82633a004352"},
    })
    body = client.get(f"/jobs/{job['id']}/worksheet", headers=headers).json()
    assert body["values"]["vin"] == "1HGCM82633A004352"


def test_blank_values_are_dropped_and_trade_can_change(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    client.put(f"/jobs/{job['id']}/worksheet", headers=headers, json={
        "trade": "electrician", "values": {"circuit": "A1", "permit_number": ""},
    })
    changed = client.put(f"/jobs/{job['id']}/worksheet", headers=headers, json={
        "trade": "plumber", "values": {"leak_check": "Fail"},
    }).json()
    assert changed["trade"] == "plumber"
    assert changed["values"] == {"leak_check": "Fail"}


@pytest.mark.parametrize("trade, values, message", [
    ("roofer", {}, "Unknown trade"),
    ("electrician", {"bogus": "x"}, "Unknown worksheet field"),
    ("electrician", {"wire_gauge": "13 AWG"}, "Wire gauge"),
    ("electrician", {"breaker_amps": 5000}, "Breaker size"),
    ("electrician", {"breaker_amps": "20"}, "Breaker size"),
    ("electrician", {"gfci_afci_tested": "yes"}, "GFCI"),
    ("electrician", {"circuit": "x" * 201}, "Circuit"),
    ("mechanic", {"vin": "1HGCM82633A00435O"}, "VIN"),
    ("mechanic", {"vin": "SHORT"}, "VIN"),
])
def test_invalid_values_are_rejected(account, trade, values, message):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    response = client.put(f"/jobs/{job['id']}/worksheet", headers=headers, json={
        "trade": trade, "values": values,
    })
    assert response.status_code == 422
    assert message in response.json()["detail"]


def test_worksheet_can_be_deleted(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    client.put(f"/jobs/{job['id']}/worksheet", headers=headers, json={
        "trade": "carpenter", "values": {"structural": False},
    })
    assert client.delete(f"/jobs/{job['id']}/worksheet", headers=headers).status_code == 204
    assert client.get(f"/jobs/{job['id']}/worksheet", headers=headers).json() is None


# Sketches


def upload(client, headers, job_id, image_url, subject="Kitchen outlet layout"):
    return client.post(
        f"/jobs/{job_id}/sketches",
        headers=headers,
        json={"subject": subject, "image": image_url},
    )


def test_sketch_upload_list_and_download(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    created = upload(client, headers, job["id"], data_url(drawing()))
    assert created.status_code == 201, created.text
    sketch = created.json()
    assert sketch["subject"] == "Kitchen outlet layout"
    assert sketch["content_type"] == "image/png"  # line drawings stay PNG
    assert (sketch["width"], sketch["height"]) == (400, 300)

    listed = client.get(f"/jobs/{job['id']}/sketches", headers=headers).json()
    assert [s["id"] for s in listed] == [sketch["id"]]

    image = client.get(f"/sketches/{sketch['id']}/image", headers=headers)
    assert image.status_code == 200
    assert image.headers["content-type"] == "image/png"
    assert image.headers["x-content-type-options"] == "nosniff"
    assert Image.open(io.BytesIO(image.content)).size == (400, 300)


def test_photo_metadata_such_as_gps_is_removed(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    photo = Image.merge("RGB", [Image.effect_noise((600, 400), 60) for _ in range(3)])
    exif = Image.Exif()
    exif[0x010F] = "PhoneMaker"           # camera make
    exif[0x8825] = {1: "N", 2: (41.0, 52.0, 0.0)}  # GPS info
    created = upload(
        client, headers, job["id"],
        data_url(photo, "JPEG", exif=exif.tobytes()),
        subject="Site photo",
    ).json()
    assert created["content_type"] == "image/jpeg"
    stored = client.get(f"/sketches/{created['id']}/image", headers=headers)
    assert len(Image.open(io.BytesIO(stored.content)).getexif()) == 0


def test_large_images_are_scaled_down(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    created = upload(
        client, headers, job["id"], data_url(Image.new("L", (4000, 1000), 255))
    ).json()
    assert max(created["width"], created["height"]) == 2000


@pytest.mark.parametrize("image_url, message", [
    ("data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=", "PNG, JPEG or WebP"),
    ("https://example.com/sketch.png", "PNG, JPEG or WebP"),
    ("data:image/png;base64," + base64.b64encode(b"not really a png").decode(),
     "could not be read"),
    ("data:image/png;base64,", "PNG, JPEG or WebP"),
])
def test_non_images_are_rejected(account, image_url, message):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    response = upload(client, headers, job["id"], image_url)
    assert response.status_code == 422
    assert message in response.json()["detail"]


def test_gif_disguised_as_png_is_rejected(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    buffer = io.BytesIO()
    Image.new("RGB", (10, 10)).save(buffer, format="GIF")
    disguised = "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode()
    response = upload(client, headers, job["id"], disguised)
    assert response.status_code == 422


def test_upload_over_5_mb_is_rejected(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    payload = base64.b64encode(b"\x89PNG" + b"0" * (5 * 1024 * 1024)).decode()
    response = upload(client, headers, job["id"], "data:image/png;base64," + payload)
    assert response.status_code == 422
    assert "5 MB" in response.json()["detail"]


def test_request_far_over_the_limit_is_rejected_early(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    response = upload(client, headers, job["id"], "data:image/png;base64," + "A" * 7_300_000)
    assert response.status_code == 422
    assert response.json()["detail"].startswith("Sketch file:")


def test_decompression_bomb_is_rejected(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    # Tiny file, 48 million pixels once decoded.
    bomb = data_url(Image.new("1", (8000, 6000), 0), "PNG", optimize=True)
    response = upload(client, headers, job["id"], bomb)
    assert response.status_code == 422


def test_subject_is_required_and_limited(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    assert upload(client, headers, job["id"], data_url(drawing()), subject="  ").status_code == 422
    assert upload(client, headers, job["id"], data_url(drawing()), subject="s" * 121).status_code == 422


def test_sketches_per_job_are_limited(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    url = data_url(drawing())
    for n in range(10):
        assert upload(client, headers, job["id"], url, subject=f"Sketch {n}").status_code == 201
    eleventh = upload(client, headers, job["id"], url, subject="One too many")
    assert eleventh.status_code == 409


def test_sketch_can_be_deleted_before_approval(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    sketch = upload(client, headers, job["id"], data_url(drawing())).json()
    assert client.delete(f"/sketches/{sketch['id']}", headers=headers).status_code == 204
    assert client.get(f"/sketches/{sketch['id']}/image", headers=headers).status_code == 404


# Ownership


def test_other_users_cannot_reach_worksheets_or_sketches(account, register_verified_user):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    client.put(f"/jobs/{job['id']}/worksheet", headers=headers, json={
        "trade": "plumber", "values": {"leak_check": "Pass"},
    })
    sketch = upload(client, headers, job["id"], data_url(drawing())).json()

    intruder = register_verified_user("intruder@example.com", PASSWORD)["headers"]
    attempts = [
        client.get(f"/jobs/{job['id']}/worksheet", headers=intruder),
        client.put(f"/jobs/{job['id']}/worksheet", headers=intruder,
                   json={"trade": "plumber", "values": {}}),
        client.delete(f"/jobs/{job['id']}/worksheet", headers=intruder),
        client.get(f"/jobs/{job['id']}/sketches", headers=intruder),
        upload(client, intruder, job["id"], data_url(drawing())),
        client.get(f"/sketches/{sketch['id']}/image", headers=intruder),
        client.delete(f"/sketches/{sketch['id']}", headers=intruder),
    ]
    assert [r.status_code for r in attempts] == [404] * len(attempts)
    # The owner's data is untouched.
    assert client.get(f"/jobs/{job['id']}/worksheet", headers=headers).json()["values"] == {
        "leak_check": "Pass"
    }


def test_deleting_a_job_removes_its_worksheet_and_sketches(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    client.put(f"/jobs/{job['id']}/worksheet", headers=headers, json={
        "trade": "welder", "values": {"process": "Other"},
    })
    sketch = upload(client, headers, job["id"], data_url(drawing())).json()
    assert client.delete(f"/jobs/{job['id']}", headers=headers).status_code == 204
    assert client.get(f"/sketches/{sketch['id']}/image", headers=headers).status_code == 404


# PDF and approval snapshot


def approved_report(client, headers, job_id):
    report = client.post(
        f"/jobs/{job_id}/reports/draft", headers=headers,
        json={"notes": "Replaced the panel."},
    ).json()
    assert client.post(f"/reports/{report['id']}/approve", headers=headers).status_code == 200
    return report


def test_pdf_prints_the_worksheet_and_sketches(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    client.put(f"/jobs/{job['id']}/worksheet", headers=headers, json={
        "trade": "electrician", "values": SAMPLE_VALUES["electrician"],
        "notes": "Labelled all breakers.",
    })
    upload(client, headers, job["id"], data_url(drawing()), subject="Panel layout")
    report = approved_report(client, headers, job["id"])

    pdf = client.get(f"/reports/{report['id']}/pdf", headers=headers)
    assert pdf.status_code == 200
    text = pdf_text(pdf.content)
    assert "Electrician worksheet" in text
    assert "Breaker size" in text and "20 A" in text
    assert "GFCI/AFCI tested" in text and "Yes" in text
    assert "Labelled all breakers." in text
    assert "Sketch: Panel layout" in text
    images = [img for page in PdfReader(io.BytesIO(pdf.content)).pages for img in page.images]
    assert len(images) == 1


def test_approved_pdf_does_not_change_when_the_worksheet_does(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    client.put(f"/jobs/{job['id']}/worksheet", headers=headers, json={
        "trade": "plumber", "values": {"leak_check": "Pass"},
    })
    sketch = upload(client, headers, job["id"], data_url(drawing()), subject="Pipe run").json()
    report = approved_report(client, headers, job["id"])

    # Later edits: a different value and a new sketch.
    client.put(f"/jobs/{job['id']}/worksheet", headers=headers, json={
        "trade": "plumber", "values": {"leak_check": "Fail"},
    })
    upload(client, headers, job["id"], data_url(drawing()), subject="Added later")

    text = pdf_text(client.get(f"/reports/{report['id']}/pdf", headers=headers).content)
    assert "Pass" in text and "Fail" not in text
    assert "Pipe run" in text and "Added later" not in text

    # The approved sketch is locked; the later one is not.
    listed = {s["subject"]: s["locked"] for s in client.get(
        f"/jobs/{job['id']}/sketches", headers=headers).json()}
    assert listed == {"Pipe run": True, "Added later": False}
    blocked = client.delete(f"/sketches/{sketch['id']}", headers=headers)
    assert blocked.status_code == 409


def test_reports_without_a_worksheet_still_export(account):
    client, headers = account["client"], account["headers"]
    job = make_job(client, headers)
    report = approved_report(client, headers, job["id"])
    pdf = client.get(f"/reports/{report['id']}/pdf", headers=headers)
    assert pdf.status_code == 200
    assert "worksheet" not in pdf_text(pdf.content).lower()
