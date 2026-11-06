"""Server glue: uvicorn listener options, TLS preflight gate."""
from __future__ import annotations

import pytest
from conftest import make_cfg

from phptopwn.server import MissingCertificate, _uvicorn_config, preflight


def test_uvicorn_config_defaults():
    cfg = make_cfg()
    config = _uvicorn_config(object(), cfg, 8080)
    assert config.host == "0.0.0.0"
    assert config.port == 8080
    assert config.log_config == {"version": 1, "disable_existing_loggers": False}
    assert config.access_log is False
    assert config.server_header is False
    assert config.proxy_headers is False
    assert config.limit_concurrency == 200


def test_uvicorn_config_zero_disables_concurrency_cap():
    cfg = make_cfg(MAX_CONCURRENCY="0")
    config = _uvicorn_config(object(), cfg, 8081)
    assert config.limit_concurrency is None


def test_uvicorn_config_tls_adds_certificate_paths():
    cfg = make_cfg(CERT_FILE="/opt/certs/a.crt", KEY_FILE="/opt/certs/a.key")
    config = _uvicorn_config(object(), cfg, 8443, tls=True)
    assert config.ssl_certfile == "/opt/certs/a.crt"
    assert config.ssl_keyfile == "/opt/certs/a.key"


def test_preflight_passes_when_certificates_exist(tmp_path):
    cert = tmp_path / "honeypot.crt"
    key = tmp_path / "honeypot.key"
    cert.write_bytes(b"cert")
    key.write_bytes(b"key")
    cfg = make_cfg(
        tmp_path, TLS="true", CERT_FILE=str(cert), KEY_FILE=str(key), LOG_DIR=str(tmp_path / "logs")
    )
    preflight(cfg)  # no exception


def test_preflight_missing_certificate_message(tmp_path):
    cfg = make_cfg(tmp_path, TLS="true", CERT_FILE=tmp_path / "nope.crt", KEY_FILE=tmp_path / "nope.key")
    with pytest.raises(MissingCertificate, match="certificate files are missing"):
        preflight(cfg)
