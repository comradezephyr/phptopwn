"""Sensor configuration: built-in defaults, optional TOML file, env overrides.

Precedence: defaults < TOML file < environment < CLI flags. Env vars are named
``PHPTOPWN_<FIELD>`` using the field name only, e.g. ``storage.max_body_bytes``
becomes ``PHPTOPWN_MAX_BODY_BYTES``. Relative paths resolve against the
current working directory.
"""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any, get_type_hints

SEVERITIES = ("info", "low", "medium", "high", "critical")

_CONFIG_ENV = "PHPTOPWN_CONFIG"
_DEFAULT_FILE = "phptopwn.toml"
_MAX_PORT = 65535


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class SensorConfig:
    host: str = "0.0.0.0"
    http_port: int = 8080
    tls_port: int = 8443
    tls_enabled: bool = False
    cert_file: Path = field(default_factory=lambda: Path("certs/honeypot.crt"))
    key_file: Path = field(default_factory=lambda: Path("certs/honeypot.key"))
    trust_proxy_headers: bool = False


@dataclass(frozen=True)
class StorageConfig:
    log_dir: Path = field(default_factory=lambda: Path("logs"))
    capture_dir: Path = field(default_factory=lambda: Path("captured_payloads"))
    max_body_bytes: int = 32 * 1024 * 1024
    probe_bytes: int = 2 * 1024 * 1024
    max_artifact_bytes: int = 4 * 1024 * 1024
    max_artifact_parts: int = 8
    body_timeout_seconds: float = 30.0
    neutralize_capture_names: bool = True


@dataclass(frozen=True)
class LimitsConfig:
    max_concurrency: int = 200
    max_concurrent_per_ip: int = 32
    rate_limit_per_minute: int = 600
    max_request_headers: int = 128
    max_header_bytes: int = 32768


@dataclass(frozen=True)
class RetentionConfig:
    max_capture_files: int = 5000
    max_age_days: int = 30
    max_log_bytes: int = 50 * 1024 * 1024
    max_log_archives: int = 5
    sweep_interval_seconds: int = 600


@dataclass(frozen=True)
class DetectionConfig:
    large_multipart_bytes: int = 1024 * 1024
    many_parts: int = 32
    part_header_bytes: int = 4096
    header_count: int = 60
    header_bytes: int = 16384
    slow_gap_seconds: float = 2.0
    slow_total_seconds: float = 5.0
    log_all_requests: bool = True


@dataclass(frozen=True)
class AlertsConfig:
    webhook_url: str = ""
    min_severity: str = "high"
    cooldown_seconds: float = 60.0
    timeout_seconds: float = 5.0
    max_inflight: int = 8


@dataclass(frozen=True)
class DecoyConfig:
    server_token: str = "Apache/2.4.52 (Ubuntu)"
    powered_by: str = "PHP/8.1.2"
    php_version: str = "8.1.2"
    memory_limit: str = "128M"
    server_name: str = "intranet.acme.local"


@dataclass(frozen=True)
class InternalConfig:
    metrics_host: str = "127.0.0.1"
    metrics_port: int = 9091


@dataclass(frozen=True)
class FleetConfig:
    """Central forwarder: ship events to the regional collector, buffer on outage."""

    enabled: bool = False
    node_id: str = ""
    region: str = ""
    collector_url: str = ""
    collector_token: str = ""
    buffer_dir: Path = field(default_factory=lambda: Path("fleet"))
    batch_max: int = 256
    batch_max_bytes: int = 4 * 1024 * 1024
    flush_interval_seconds: float = 3.0
    timeout_seconds: float = 10.0
    max_buffer_bytes: int = 256 * 1024 * 1024


@dataclass(frozen=True)
class LoggingConfig:
    level: str = "INFO"
    json: bool = True


@dataclass(frozen=True)
class Config:
    sensor: SensorConfig = field(default_factory=SensorConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    retention: RetentionConfig = field(default_factory=RetentionConfig)
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    decoy: DecoyConfig = field(default_factory=DecoyConfig)
    internal: InternalConfig = field(default_factory=InternalConfig)
    fleet: FleetConfig = field(default_factory=FleetConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


_SECTION_TYPES = {
    "sensor": SensorConfig,
    "storage": StorageConfig,
    "limits": LimitsConfig,
    "retention": RetentionConfig,
    "detection": DetectionConfig,
    "alerts": AlertsConfig,
    "decoy": DecoyConfig,
    "internal": InternalConfig,
    "fleet": FleetConfig,
    "logging": LoggingConfig,
}

# Field names that should not follow the PHPTOPWN_<FIELD> env rule.
_ENV_RENAMES = {
    ("sensor", "tls_enabled"): "PHPTOPWN_TLS",
    ("detection", "log_all_requests"): "PHPTOPWN_LOG_ALL",
    ("logging", "level"): "PHPTOPWN_LOG_LEVEL",
    ("logging", "json"): "PHPTOPWN_LOG_JSON",
}


def env_name(section: str, fname: str) -> str:
    return _ENV_RENAMES.get((section, fname), f"PHPTOPWN_{fname.upper()}")


def _coerce(value: Any, hint: type, label: str) -> Any:
    try:
        if hint is str:
            return str(value)
        if hint is bool:
            if isinstance(value, bool):
                return value
            if isinstance(value, int):
                return bool(value)
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "on"}
            raise ValueError(f"{value!r} is not boolean")
        if hint is int:
            if isinstance(value, bool):
                raise ValueError("use an integer, not a boolean")
            return int(value)
        if hint is float:
            return float(value)
        if hint is Path:
            return Path(str(value)).expanduser()
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{label}: {exc}") from exc
    raise ConfigError(f"{label}: unsupported type {hint}")


def _build_section(name: str, cls: type, values: dict[str, Any], env: dict[str, str]) -> Any:
    valid = {f.name for f in fields(cls)}
    unknown = set(values) - valid
    if unknown:
        raise ConfigError(f"unknown key in [{name}]: {', '.join(sorted(unknown))}")
    hints = get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for fname in valid:
        hint = hints[fname]
        label = f"{name}.{fname}"
        env_key = env_name(name, fname)
        env_raw = env.get(env_key)
        if env_raw:
            kwargs[fname] = _coerce(env_raw, hint, label)
        elif fname in values:
            raw = values[fname]
            if not isinstance(raw, (str, bool, int, float)):
                raise ConfigError(f"{label}: expected scalar value, got {type(raw).__name__}")
            kwargs[fname] = _coerce(raw, hint, label)
    return cls(**kwargs)


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path}: top level must be a table")
    return data


def _validate(cfg: Config) -> None:
    ports = {
        "http_port": cfg.sensor.http_port,
        "tls_port": cfg.sensor.tls_port,
        "metrics_port": cfg.internal.metrics_port,
    }
    for label, port in ports.items():
        if not 1 <= port <= _MAX_PORT:
            raise ConfigError(f"control: {label}={port} is not a valid port")
    if len(set(ports.values())) != len(ports):
        raise ConfigError("control: every port must be distinct")
    if cfg.internal.metrics_host.strip() == "":
        raise ConfigError("internal: metrics_host must not be empty")
    if cfg.sensor.host.strip() == "":
        raise ConfigError("sensor: host must not be empty")
    s = cfg.storage
    if s.probe_bytes > s.max_body_bytes:
        raise ConfigError("storage: probe_bytes must be <= max_body_bytes")
    if s.max_artifact_bytes > s.max_body_bytes:
        raise ConfigError("storage: max_artifact_bytes must be <= max_body_bytes")
    if s.max_artifact_parts < 1 or s.max_artifact_parts > 64:
        raise ConfigError("storage: max_artifact_parts must be between 1 and 64")
    if s.body_timeout_seconds < 0.2:
        raise ConfigError("storage: body_timeout_seconds must be at least 0.2")
    if s.max_body_bytes < 1024:
        raise ConfigError("storage: max_body_bytes must be at least 1024")
    d = cfg.detection
    if d.large_multipart_bytes < 256:
        raise ConfigError("detection: large_multipart_bytes must be at least 256")
    if d.many_parts < 2:
        raise ConfigError("detection: many_parts must be at least 2")
    if d.part_header_bytes < 128:
        raise ConfigError("detection: part_header_bytes must be at least 128")
    if d.header_count < 5:
        raise ConfigError("detection: header_count must be at least 5")
    if d.header_bytes < 512:
        raise ConfigError("detection: header_bytes must be at least 512")
    if d.slow_gap_seconds < 0.01:
        raise ConfigError("detection: slow_gap_seconds must be at least 0.01")
    if d.slow_total_seconds < 0.01:
        raise ConfigError("detection: slow_total_seconds must be at least 0.01")
    if cfg.alerts.min_severity not in SEVERITIES:
        raise ConfigError("alerts: min_severity must be one of " + ", ".join(SEVERITIES))
    if cfg.alerts.cooldown_seconds < 0:
        raise ConfigError("alerts: cooldown_seconds must be >= 0")
    if cfg.alerts.max_inflight < 1:
        raise ConfigError("alerts: max_inflight must be at least 1")
    if cfg.limits.rate_limit_per_minute < 0:
        raise ConfigError("limits: rate_limit_per_minute must be >= 0 (0 disables)")
    if cfg.limits.max_concurrent_per_ip < 0:
        raise ConfigError("limits: max_concurrent_per_ip must be >= 0 (0 disables)")
    if cfg.limits.max_concurrency < 0:
        raise ConfigError("limits: max_concurrency must be >= 0 (0 disables)")
    if cfg.limits.max_request_headers < 8:
        raise ConfigError("limits: max_request_headers must be at least 8")
    if cfg.limits.max_header_bytes < 1024:
        raise ConfigError("limits: max_header_bytes must be at least 1024")
    r = cfg.retention
    if r.max_capture_files < 1:
        raise ConfigError("retention: max_capture_files must be at least 1")
    if r.max_age_days < 1:
        raise ConfigError("retention: max_age_days must be at least 1")
    if r.max_log_bytes < 1024:
        raise ConfigError("retention: max_log_bytes must be at least 1024")
    if r.max_log_archives < 0:
        raise ConfigError("retention: max_log_archives must be >= 0")
    if r.sweep_interval_seconds < 5:
        raise ConfigError("retention: sweep_interval_seconds must be at least 5")
    f = cfg.fleet
    if f.enabled:
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", f.node_id):
            raise ConfigError("fleet: node_id must be 1-64 chars of [a-z0-9-]")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", f.region):
            raise ConfigError("fleet: region must be 1-64 chars of [a-z0-9-]")
        url = f.collector_url[:-1] if f.collector_url.endswith("/") else f.collector_url
        allowed_insecure = "http://localhost" in url or "http://127.0.0.1" in url
        if not (url.startswith("https://") or allowed_insecure):
            raise ConfigError(
                "fleet: collector_url must be an https:// URL "
                "(http:// only to loopback hosts for lab testing)"
            )
        if len(f.collector_token) < 32 or any(ch.isspace() for ch in f.collector_token):
            raise ConfigError("fleet: collector_token must be at least 32 chars without whitespace")
        if f.buffer_dir == cfg.storage.log_dir:
            raise ConfigError("fleet: buffer_dir must not be the log_dir")
        if not 16 <= f.batch_max <= 4096:
            raise ConfigError("fleet: batch_max must be between 16 and 4096")
        if not 65536 <= f.batch_max_bytes <= 16 * 1024 * 1024:
            raise ConfigError("fleet: batch_max_bytes must be between 64 KiB and 16 MiB")
        if not 0.5 <= f.flush_interval_seconds <= 600:
            raise ConfigError("fleet: flush_interval_seconds must be between 0.5 and 600")
        if not 1.0 <= f.timeout_seconds <= 120:
            raise ConfigError("fleet: timeout_seconds must be between 1 and 120")
        if f.max_buffer_bytes < 4 * f.batch_max_bytes:
            raise ConfigError("fleet: max_buffer_bytes must be at least 4x batch_max_bytes")


def load_config(
    config_path: Path | str | None = None,
    environ: dict[str, str] | None = None,
    overrides: dict[str, Any] | None = None,
) -> Config:
    env = dict(os.environ if environ is None else environ)
    path = config_path
    if path is None:
        raw = env.get(_CONFIG_ENV)
        if raw:
            path = Path(raw)
    if path is None and Path(_DEFAULT_FILE).is_file():
        path = Path(_DEFAULT_FILE)
    data: dict[str, Any] = {}
    if path is not None:
        data = _read_toml(Path(path))
    sections = {}
    unknown_tables = set(data) - set(_SECTION_TYPES)
    if unknown_tables:
        raise ConfigError(f"unknown config section(s): {', '.join(sorted(unknown_tables))}")
    for name, cls in _SECTION_TYPES.items():
        raw_section = data.get(name, {})
        if not isinstance(raw_section, dict):
            raise ConfigError(f"[{name}]: must be a table")
        sections[name] = _build_section(name, cls, raw_section, env)
    cfg = Config(**sections)
    if overrides:
        sensor = cfg.sensor
        if overrides.get("host") is not None:
            sensor = replace(sensor, host=str(overrides["host"]))
        if overrides.get("http_port") is not None:
            sensor = replace(sensor, http_port=int(overrides["http_port"]))
        cfg = replace(cfg, sensor=sensor)
    _validate(cfg)
    return cfg


def dry_run_report(cfg: Config, source: str) -> str:
    s, st, t, d, a = cfg.sensor, cfg.storage, cfg.limits, cfg.detection, cfg.alerts
    alerts = a.webhook_url or "disabled"
    tls = f"on ({s.cert_file})" if s.tls_enabled else "off"
    lines = [
        "phptopwn dry run",
        f"config source: {source}",
        f"listener:      http://{s.host}:{s.http_port}  tls {tls}",
        f"internal:      http://{cfg.internal.metrics_host}:{cfg.internal.metrics_port} (/healthz, /metrics)",
        f"storage:       logs {st.log_dir}  captures {st.capture_dir}",
        f"body limits:   {st.max_body_bytes} B, probe {st.probe_bytes} B,"
        f" artifact {st.max_artifact_bytes} B x {st.max_artifact_parts}",
        f"limits:        {t.rate_limit_per_minute or 'no'} req/min/IP, {t.max_concurrent_per_ip or 'no'} concurrent/IP,"
        f" {t.max_request_headers} headers",
        f"detection:     multipart >= {d.large_multipart_bytes} B, >= {d.many_parts} parts,"
        f" headers >= {d.header_count}/{d.header_bytes} B, gap >= {d.slow_gap_seconds}s",
        f"alerts:        {alerts}, min severity {a.min_severity}, cooldown {a.cooldown_seconds}s",
        f"retention:     {cfg.retention.max_capture_files} files / {cfg.retention.max_age_days} days,"
        f" logs rotate at {cfg.retention.max_log_bytes} B",
        f"decoy:         {cfg.decoy.server_token} ({cfg.decoy.php_version}) at {cfg.decoy.server_name}",
    ]
    if cfg.fleet.enabled:
        lines.append(
            f"fleet:         -> {cfg.fleet.collector_url}"
            f" (node {cfg.fleet.node_id}, region {cfg.fleet.region})"
        )
    else:
        lines.append("fleet:         disabled")
    if s.tls_enabled and not (s.cert_file.exists() and s.key_file.exists()):
        lines.append(f"warning: tls enabled but {s.cert_file} / {s.key_file} not found")
    return "\n".join(lines)
