"""Configuration loading: precedence, env renames, validation, dry-run report."""
from __future__ import annotations

import pytest

from phptopwn.config import SEVERITIES, ConfigError, dry_run_report, load_config

CLEAN_ENV: dict[str, str] = {}


def test_defaults_without_anything(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # no phptopwn.toml in the workspace copy
    cfg = load_config(environ=CLEAN_ENV)
    assert cfg.sensor.http_port == 8080
    assert cfg.internal.metrics_port == 9091
    assert cfg.logging.json is True
    assert cfg.alerts.webhook_url == ""


def test_toml_file_is_used(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "custom.toml").write_text(
        '[sensor]\nhttp_port = 9100\n[alerts]\nmin_severity = "critical"\n',
        encoding="utf-8",
    )
    cfg = load_config(tmp_path / "custom.toml", environ=CLEAN_ENV)
    assert cfg.sensor.http_port == 9100
    assert cfg.alerts.min_severity == "critical"
    assert cfg.sensor.host == "0.0.0.0"  # untouched section keeps defaults


def test_env_beats_toml_and_empty_env_is_unset(tmp_path):
    (tmp_path / "custom.toml").write_text("[sensor]\nhttp_port = 9100\n", encoding="utf-8")
    cfg = load_config(
        tmp_path / "custom.toml",
        environ={"PHPTOPWN_HTTP_PORT": "9200", "PHPTOPWN_HOST": ""},
    )
    assert cfg.sensor.http_port == 9200
    assert cfg.sensor.host == "0.0.0.0"


def test_cli_overrides_beat_env():
    cfg = load_config(
        environ={"PHPTOPWN_HTTP_PORT": "9200"},
        overrides={"host": "127.0.0.1", "http_port": 9300},
    )
    assert cfg.sensor.http_port == 9300
    assert cfg.sensor.host == "127.0.0.1"


def test_env_renames_plus_field_rule(tmp_path):
    (tmp_path / "custom.toml").write_text(
        '[logging]\nlevel = "INFO"\njson = true\n',
        encoding="utf-8",
    )
    cfg = load_config(
        environ={
            "PHPTOPWN_TLS": "true",
            "PHPTOPWN_LOG_ALL": "false",
            "PHPTOPWN_LOG_LEVEL": "debug",
            "PHPTOPWN_LOG_JSON": "no",
            "PHPTOPWN_HEADER_COUNT": "33",
        }
    )
    assert cfg.sensor.tls_enabled is True
    assert cfg.detection.log_all_requests is False
    assert cfg.logging.level == "debug"
    assert cfg.logging.json is False
    assert cfg.detection.header_count == 33


@pytest.mark.parametrize("truthy", ["1", "true", "YES", "on"])
def test_boolean_env_coercion(tmp_path, truthy):
    (tmp_path / "custom.toml").write_text("[detection]\nlog_all_requests = false\n")
    cfg = load_config(environ={"PHPTOPWN_LOG_ALL": truthy})
    assert cfg.detection.log_all_requests is True


def test_int_env_coercion_errors():
    with pytest.raises(ConfigError):
        load_config(environ={"PHPTOPWN_HTTP_PORT": "not-a-port"})


def test_unknown_toml_key_rejected(tmp_path):
    (tmp_path / "bad.toml").write_text("[storage]\nmax_bodies = 3\n")
    with pytest.raises(ConfigError, match="max_bodies"):
        load_config(tmp_path / "bad.toml")


def test_invalid_toml_rejected(tmp_path):
    (tmp_path / "bad.toml").write_text("[storage]\nthis is not = = valid[[=")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_config(tmp_path / "bad.toml")


def test_port_range_and_uniqueness():
    with pytest.raises(ConfigError, match="http_port"):
        load_config(environ={"PHPTOPWN_HTTP_PORT": "70000"})
    with pytest.raises(ConfigError, match="distinct"):
        load_config(environ={"PHPTOPWN_METRICS_PORT": "8080"})


@pytest.mark.parametrize("section_key,glue", [
    ("PHPTOPWN_MIN_SEVERITY", "min_severity"),
    ("PHPTOPWN_METRICS_HOST", "metrics_host"),
])
def test_empty_string_values_are_rejected(section_key, glue):
    with pytest.raises(ConfigError):
        load_config(environ={section_key: "  "})


def test_severities_are_stable():
    assert SEVERITIES == ("info", "low", "medium", "high", "critical")


def test_dry_run_report_mentions_key_sections(tmp_path):
    cfg = load_config(environ={"PHPTOPWN_WEBHOOK_URL": "https://hook.invalid/x"})
    report = dry_run_report(cfg, "test")
    assert "listener:" in report and "8080" in report
    assert "internal:" in report and "/metrics" in report
    assert "alerts:        https://hook.invalid/x" in report
    assert "retention:" in report
