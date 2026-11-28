"""API docs and the OpenAPI schema must be hidden in production.

Found by the live deployment check: /docs and /redoc were off in production,
but /openapi.json still answered with the full route and field map.
"""
from app.main import api_docs_settings


def test_production_hides_docs_and_schema():
    assert api_docs_settings(True) == {
        "docs_url": None,
        "redoc_url": None,
        "openapi_url": None,
    }


def test_development_keeps_docs_and_schema():
    settings = api_docs_settings(False)
    assert settings["docs_url"] == "/docs"
    assert settings["openapi_url"] == "/openapi.json"


def test_test_app_still_serves_schema_outside_production(client):
    assert client.get("/openapi.json").status_code == 200
