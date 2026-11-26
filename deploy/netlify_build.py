"""Build the static frontend for Netlify.

Copies app/static into dist/static, puts index.html at the site root, writes
config.js with the API address, and writes the security headers (_headers).
Netlify runs this with the API_BASE_URL environment variable set.
"""
import json
import os
import shutil
import sys
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "app" / "static"
DIST = ROOT / "dist"


def api_origin() -> str:
    """Return the API origin, refusing anything but a plain https:// origin."""
    raw = os.environ.get("API_BASE_URL", "").strip().rstrip("/")
    parts = urlsplit(raw)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.path
        or parts.query
        or parts.fragment
        or parts.username
        or parts.password
    ):
        sys.exit("API_BASE_URL must be an https:// origin, for example https://api.example.com")
    return f"https://{parts.netloc}"


def main() -> None:
    origin = api_origin()
    if DIST.exists():
        shutil.rmtree(DIST)
    shutil.copytree(STATIC, DIST / "static")
    shutil.copy2(STATIC / "index.html", DIST / "index.html")

    (DIST / "static" / "config.js").write_text(
        "window.TRADEDESK_CONFIG = " + json.dumps({"apiBase": origin}) + ";\n",
        encoding="utf-8",
    )

    # Same policy the API sends, with the API added to connect-src.
    csp = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data: blob:; "
        f"connect-src 'self' {origin}; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'"
    )
    headers = [
        "/*",
        f"  Content-Security-Policy: {csp}",
        "  X-Content-Type-Options: nosniff",
        "  X-Frame-Options: DENY",
        "  Referrer-Policy: no-referrer",
        "  Permissions-Policy: camera=(), microphone=(), geolocation=()",
        "  Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "/static/config.js",
        "  Cache-Control: no-cache",
    ]
    (DIST / "_headers").write_text("\n".join(headers) + "\n", encoding="utf-8")
    print(f"Built dist/ for API {origin}")


if __name__ == "__main__":
    main()
