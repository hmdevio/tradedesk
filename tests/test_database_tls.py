"""PostgreSQL TLS settings (deployment to a hosted database).

The server certificate must always be verified (verify-full). A client
certificate is optional so a hosted database without mTLS can be used, but
the certificate and key must be set together.
"""
from types import SimpleNamespace

import pytest

from app.database import postgres_connect_args


def settings(**overrides):
    values = {
        "database_sslmode": "verify-full",
        "database_sslrootcert": "system",
        "database_sslcert": "",
        "database_sslkey": "",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_hosted_database_uses_verified_tls_with_system_cas():
    args = postgres_connect_args(settings())
    assert args["sslmode"] == "verify-full"
    assert args["sslrootcert"] == "system"
    assert "sslcert" not in args and "sslkey" not in args


@pytest.mark.parametrize("mode", ["require", "verify-ca", "prefer", "disable", ""])
def test_weaker_ssl_modes_are_refused(mode):
    with pytest.raises(RuntimeError, match="verify-full"):
        postgres_connect_args(settings(database_sslmode=mode))


def test_missing_root_certificate_is_refused():
    with pytest.raises(RuntimeError, match="DATABASE_SSLROOTCERT"):
        postgres_connect_args(settings(database_sslrootcert=" "))


def test_root_certificate_file_must_exist(tmp_path):
    with pytest.raises(RuntimeError, match="does not exist"):
        postgres_connect_args(settings(database_sslrootcert=str(tmp_path / "missing.crt")))


def test_client_certificate_and_key_must_be_set_together(tmp_path):
    cert = tmp_path / "client.crt"
    cert.write_text("x")
    with pytest.raises(RuntimeError, match="together"):
        postgres_connect_args(settings(database_sslcert=str(cert)))


def test_mtls_still_supported(tmp_path):
    files = {}
    for name in ("ca.crt", "client.crt", "client.key"):
        files[name] = tmp_path / name
        files[name].write_text("x")
    args = postgres_connect_args(settings(
        database_sslrootcert=str(files["ca.crt"]),
        database_sslcert=str(files["client.crt"]),
        database_sslkey=str(files["client.key"]),
    ))
    assert args["sslcert"] == str(files["client.crt"])
    assert args["sslkey"] == str(files["client.key"])
