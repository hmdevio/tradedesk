"""Trade worksheet templates, value validation and sketch image handling.

Templates are plain data so a field can be added or reworded without a
database change: saved worksheets store field keys, and labels come from
here at display and print time. Removing a key hides old values for it.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import re
from dataclasses import dataclass

from PIL import Image, UnidentifiedImageError


# Field kinds: text (one line), textarea, number, boolean, select.
def text(key, label, max_length=200):
    return {"key": key, "label": label, "type": "text", "max_length": max_length}


def textarea(key, label, max_length=2000):
    return {"key": key, "label": label, "type": "textarea", "max_length": max_length}


def number(key, label, unit, minimum, maximum):
    return {
        "key": key, "label": label, "type": "number", "unit": unit,
        "min": minimum, "max": maximum,
    }


def yes_no(key, label):
    return {"key": key, "label": label, "type": "boolean"}


def select(key, label, options):
    return {"key": key, "label": label, "type": "select", "options": options}


TRADES: dict[str, dict] = {
    "electrician": {
        "label": "Electrician",
        "fields": [
            text("panel_location", "Panel / location"),
            text("circuit", "Circuit"),
            number("breaker_amps", "Breaker size", "A", 0, 1000),
            select("wire_gauge", "Wire gauge", [
                "14 AWG", "12 AWG", "10 AWG", "8 AWG", "6 AWG", "4 AWG",
                "2 AWG", "1/0 AWG", "2/0 AWG", "Other",
            ]),
            number("voltage_reading", "Voltage reading", "V", 0, 1000),
            yes_no("gfci_afci_tested", "GFCI/AFCI tested"),
            text("permit_number", "Permit number", 60),
        ],
    },
    "plumber": {
        "label": "Plumber",
        "fields": [
            text("fixture_system", "Fixture / system"),
            select("pipe_material", "Pipe material", [
                "Copper", "PEX", "PVC", "CPVC", "ABS", "Galvanized",
                "Cast iron", "Other",
            ]),
            number("pressure_test_psi", "Pressure test", "psi", 0, 500),
            select("leak_check", "Leak check", ["Pass", "Fail", "Not tested"]),
            text("water_heater", "Water heater make / model / capacity"),
            text("shutoff_location", "Shut-off location"),
        ],
    },
    "hvac": {
        "label": "HVAC technician",
        "fields": [
            select("system_type", "System type", [
                "Split AC", "Heat pump", "Furnace", "Boiler", "Mini-split",
                "Packaged unit", "Other",
            ]),
            text("equipment", "Make / model / serial"),
            select("refrigerant_type", "Refrigerant type", [
                "R-410A", "R-32", "R-454B", "R-22", "Other", "Not applicable",
            ]),
            text("refrigerant_charge", "Refrigerant charge", 60),
            text("filter_size", "Filter size", 60),
            yes_no("filter_changed", "Filter changed"),
            number("supply_temp_f", "Supply air temperature", "°F", -40, 250),
            number("return_temp_f", "Return air temperature", "°F", -40, 250),
            number("static_pressure", "Total static pressure", "in. w.c.", 0, 10),
        ],
    },
    "carpenter": {
        "label": "Carpenter",
        "fields": [
            text("area_room", "Area / room"),
            textarea("materials", "Materials and quantities"),
            textarea("measurements", "Measurements"),
            text("fasteners_finish", "Fasteners / finish"),
            yes_no("structural", "Structural work"),
        ],
    },
    "welder": {
        "label": "Welder",
        "fields": [
            select("process", "Process", [
                "MIG (GMAW)", "TIG (GTAW)", "Stick (SMAW)", "Flux-core (FCAW)",
                "Other",
            ]),
            text("base_metal", "Base metal"),
            text("thickness", "Thickness", 60),
            text("filler", "Filler / rod"),
            select("position", "Position", [
                "1G/1F flat", "2G/2F horizontal", "3G/3F vertical",
                "4G/4F overhead", "5G pipe", "6G pipe", "Other",
            ]),
            select("joint_type", "Joint type", [
                "Butt", "Fillet / T", "Lap", "Corner", "Edge", "Other",
            ]),
            select("inspection", "Inspection result", [
                "Visual - pass", "Visual - fail", "Dye penetrant",
                "Not inspected",
            ]),
        ],
    },
    "mechanic": {
        "label": "Automotive & diesel mechanic",
        "fields": [
            text("vin", "VIN", 17),
            text("vehicle", "Year / make / model"),
            text("mileage_hours", "Mileage / engine hours", 60),
            textarea("complaint", "Customer complaint"),
            text("diagnostic_codes", "Diagnostic codes"),
            textarea("parts_replaced", "Parts replaced"),
            textarea("torque_fluid_notes", "Torque / fluid notes"),
        ],
    },
}

MAX_NOTES = 4000
VIN_PATTERN = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")


class WorksheetError(ValueError):
    """Raised for invalid worksheet input; the message is safe to show."""


def public_templates() -> list[dict]:
    """Templates in display order, for the interface."""
    return [
        {"key": key, "label": spec["label"], "fields": spec["fields"]}
        for key, spec in TRADES.items()
    ]


def validate_values(trade: str, values: dict) -> dict:
    """Return cleaned values for a trade, or raise WorksheetError."""
    spec = TRADES.get(trade)
    if spec is None:
        raise WorksheetError("Unknown trade.")
    if not isinstance(values, dict):
        raise WorksheetError("Worksheet values must be an object.")

    fields = {field["key"]: field for field in spec["fields"]}
    unknown = sorted(set(values) - set(fields))
    if unknown:
        raise WorksheetError("Unknown worksheet field(s): " + ", ".join(unknown))

    cleaned: dict = {}
    for key, value in values.items():
        field = fields[key]
        label = field["label"]
        if value is None or value == "":
            continue
        kind = field["type"]
        if kind in ("text", "textarea"):
            if not isinstance(value, str):
                raise WorksheetError(f"{label} must be text.")
            value = value.strip()
            if len(value) > field["max_length"]:
                raise WorksheetError(
                    f"{label} must be at most {field['max_length']} characters."
                )
            if key == "vin" and value:
                value = value.upper()
                if not VIN_PATTERN.fullmatch(value):
                    raise WorksheetError(
                        "VIN must be 17 letters and digits (no I, O or Q)."
                    )
            if value:
                cleaned[key] = value
        elif kind == "number":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise WorksheetError(f"{label} must be a number.")
            if not field["min"] <= value <= field["max"]:
                raise WorksheetError(
                    f"{label} must be between {field['min']} and {field['max']}."
                )
            cleaned[key] = value
        elif kind == "boolean":
            if not isinstance(value, bool):
                raise WorksheetError(f"{label} must be yes or no.")
            cleaned[key] = value
        elif kind == "select":
            if value not in field["options"]:
                raise WorksheetError(f"{label} must be one of the listed options.")
            cleaned[key] = value
    return cleaned


def validate_notes(notes: str | None) -> str | None:
    if notes is None:
        return None
    notes = notes.strip()
    if len(notes) > MAX_NOTES:
        raise WorksheetError(f"Notes must be at most {MAX_NOTES} characters.")
    return notes or None


def printable_rows(trade: str, data_json: str) -> tuple[str, list[tuple[str, str]]]:
    """Return (trade label, [(field label, display value)]) for the PDF."""
    spec = TRADES.get(trade)
    try:
        data = json.loads(data_json)
    except (TypeError, ValueError):
        data = {}
    if spec is None or not isinstance(data, dict):
        return trade, []
    rows = []
    for field in spec["fields"]:
        if field["key"] not in data:
            continue
        value = data[field["key"]]
        if field["type"] == "boolean":
            shown = "Yes" if value else "No"
        elif field["type"] == "number":
            number_text = f"{value:g}" if isinstance(value, float) else str(value)
            shown = f"{number_text} {field['unit']}"
        else:
            shown = str(value)
        rows.append((field["label"], shown))
    return spec["label"], rows


# Sketch images

MAX_UPLOAD_BYTES = 5 * 1024 * 1024        # decoded upload size
MAX_SOURCE_PIXELS = 40_000_000            # refuse decompression bombs
MAX_STORED_SIDE = 2000                    # longest side after resizing
MAX_SKETCHES_PER_JOB = 10
ALLOWED_FORMATS = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp"}
DATA_URL = re.compile(
    r"^data:image/(png|jpeg|webp);base64,([A-Za-z0-9+/=\s]+)$"
)


@dataclass
class ProcessedImage:
    content: bytes
    content_type: str
    width: int
    height: int
    sha256: str


def process_sketch(data_url: str) -> ProcessedImage:
    """Decode, check and re-encode an uploaded sketch.

    Re-encoding is the security step: only pixels survive, so EXIF data
    (including phone GPS location), embedded scripts or polyglot payloads
    are dropped, and the stored file is a plain PNG or JPEG.
    """
    match = DATA_URL.fullmatch(data_url.strip())
    if match is None:
        raise WorksheetError("The sketch must be a PNG, JPEG or WebP image.")
    try:
        raw = base64.b64decode(match.group(2), validate=False)
    except (binascii.Error, ValueError):
        raise WorksheetError("The sketch file could not be read.") from None
    if not raw:
        raise WorksheetError("The sketch file is empty.")
    if len(raw) > MAX_UPLOAD_BYTES:
        raise WorksheetError("The sketch must be 5 MB or smaller.")

    try:
        with Image.open(io.BytesIO(raw)) as probe:
            if probe.format not in ALLOWED_FORMATS:
                raise WorksheetError("The sketch must be a PNG, JPEG or WebP image.")
            if probe.width * probe.height > MAX_SOURCE_PIXELS:
                raise WorksheetError("The sketch has too many pixels.")
            probe.verify()
        with Image.open(io.BytesIO(raw)) as image:
            image.load()
            image = _flatten(image)
    except WorksheetError:
        raise
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        raise WorksheetError("The sketch file could not be read as an image.") from None

    image.thumbnail((MAX_STORED_SIDE, MAX_STORED_SIDE))
    output = io.BytesIO()
    if image.mode == "L" or _looks_like_drawing(image):
        image.save(output, format="PNG", optimize=True)
        content_type = "image/png"
    else:
        image.save(output, format="JPEG", quality=85, optimize=True)
        content_type = "image/jpeg"
    content = output.getvalue()
    return ProcessedImage(
        content=content,
        content_type=content_type,
        width=image.width,
        height=image.height,
        sha256=hashlib.sha256(content).hexdigest(),
    )


def _flatten(image: Image.Image) -> Image.Image:
    """Convert to RGB (or grayscale), painting transparency onto white."""
    if image.mode in ("RGBA", "LA") or (image.mode == "P" and "transparency" in image.info):
        rgba = image.convert("RGBA")
        background = Image.new("RGB", rgba.size, (255, 255, 255))
        background.paste(rgba, mask=rgba.getchannel("A"))
        return background
    if image.mode in ("1", "L", "I;16", "I"):
        return image.convert("L")
    return image.convert("RGB")


def _looks_like_drawing(image: Image.Image) -> bool:
    """Few colours means a line drawing or plot: keep it sharp as PNG."""
    sample = image.copy()
    sample.thumbnail((200, 200))
    colours = sample.getcolors(maxcolors=4096)
    return colours is not None and len(colours) <= 256
