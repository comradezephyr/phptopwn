"""Process glue: uvicorn listeners, logging bootstrap, graceful shutdown."""
from __future__ import annotations

import asyncio
import logging

import uvicorn

from .config import Config
from .decoy import create_app
from .metrics import build_internal_app
from .runtime import Sensor

LOG = logging.getLogger("phptopwn.server")


def setup_logging(cfg: Config) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(cfg.logging.level.upper())
    logging.getLogger("phptopwn").setLevel(cfg.logging.level.upper())


def _uvicorn_config(app: object, cfg: Config, port: int, tls: bool = False) -> uvicorn.Config:
    options: dict = {
        "host": cfg.sensor.host,
        "port": port,
        "log_level": cfg.logging.level.lower(),
        "access_log": False,
        "server_header": False,
        "proxy_headers": False,
        "timeout_keep_alive": 15,
        "lifespan": "on",
    }
    limit = cfg.limits.max_concurrency
    if limit > 0:
        options["limit_concurrency"] = limit
    if tls:
        options["ssl_certfile"] = str(cfg.sensor.cert_file)
        options["ssl_keyfile"] = str(cfg.sensor.key_file)
    return uvicorn.Config(app, **options)


def preflight(cfg: Config) -> None:
    if cfg.sensor.tls_enabled and not (
        cfg.sensor.cert_file.exists() and cfg.sensor.key_file.exists()
    ):
        raise MissingCertificate(
            f"tls_enabled but certificate files are missing: "
            f"{cfg.sensor.cert_file} / {cfg.sensor.key_file}"
        )


class MissingCertificate(RuntimeError):
    pass


async def serve_async(cfg: Config, sensor: Sensor) -> None:
    app = create_app(cfg, sensor)
    internal_app = build_internal_app(sensor)
    servers: list[uvicorn.Server] = [
        uvicorn.Server(_uvicorn_config(app, cfg, cfg.sensor.http_port))
    ]

    internal = uvicorn.Server(_uvicorn_config(internal_app, cfg, cfg.internal.metrics_port))
    internal.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    servers.append(internal)

    if cfg.sensor.tls_enabled:
        tls_server = uvicorn.Server(_uvicorn_config(app, cfg, cfg.sensor.tls_port, tls=True))
        # Only the primary server owns signal handling; the others share it.
        tls_server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
        servers.append(tls_server)

    sensor.start_maintenance()

    banner = f"phptopwn listening on http://{cfg.sensor.host}:{cfg.sensor.http_port}"
    if cfg.sensor.tls_enabled:
        banner += f" and https://{cfg.sensor.host}:{cfg.sensor.tls_port}"
    banner += f" | internal {cfg.internal.metrics_host}:{cfg.internal.metrics_port}"
    LOG.info(banner)
    LOG.info(
        "telemetry -> %s | captures -> %s",
        sensor.store.log_path,
        cfg.storage.capture_dir,
    )
    print(banner, flush=True)

    try:
        await asyncio.gather(*(server.serve() for server in servers))
    finally:
        await sensor.shutdown()


def serve(cfg: Config) -> None:
    setup_logging(cfg)
    sensor = Sensor(cfg)
    try:
        preflight(cfg)
    except MissingCertificate as exc:
        raise SystemExit(f"phptopwn: {exc}") from exc
    sensor.open()
    try:
        asyncio.run(serve_async(cfg, sensor))
    except KeyboardInterrupt:  # pragma: no cover - interactive shutdown
        pass
