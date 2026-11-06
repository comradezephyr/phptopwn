"""Operator CLI for the regional collector.

``phptopwn-collect serve`` runs the ingest/dashboard service under uvicorn,
mirroring the sensor's TLS handling. ``phptopwn-collect ioc`` aggregates one
raw day into IOC artefacts plus a SHA-256 manifest. Neither command sends
data anywhere; the ioc command exits non-zero when the target day is absent
or artefacts already exist without ``--force``.
"""
from __future__ import annotations

import argparse
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

from .collector import (
    CollectConfig,
    CollectConfigError,
    EventStore,
    create_collector_app,
    read_collect_config,
)

_DESCRIPTION = "phptopwn fleet collector: event ingest and IOC export."

try:  # pyproject-declared version, identical to phptopwn.__version__
    _VERSION = metadata.version("phptopwn")
except metadata.PackageNotFoundError:  # pragma: no cover - source-tree runs
    _VERSION = "unknown"


class MissingCertificate(RuntimeError):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phptopwn-collect", description=_DESCRIPTION)
    parser.add_argument("--version", action="version", version=f"phptopwn-collect {_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the collector ingest service")
    serve.add_argument("--config", type=Path, default=Path("phptopwn.toml"), metavar="PATH")
    serve.add_argument("--host", default=None, help="override the bind address")
    serve.add_argument("--port", type=int, default=None, help="override the listen port")

    ioc = sub.add_parser("ioc", help="export IOC artefacts for one raw day")
    ioc.add_argument("--day", required=True, metavar="YYYYMMDD")
    ioc.add_argument("--config", type=Path, default=Path("phptopwn.toml"), metavar="PATH")
    ioc.add_argument("--out", type=Path, required=True, metavar="DIR")
    ioc.add_argument("--force", action="store_true", help="overwrite existing artefacts")
    return parser


def _check_day_format(day: str) -> bool:
    return len(day) == 8 and day.isdigit() and day != "00000000"


def serve_command(cfg: CollectConfig, node_map: dict[str, str], args: argparse.Namespace) -> int:
    if cfg.tls_enabled and not (cfg.cert_file.exists() and cfg.key_file.exists()):
        raise MissingCertificate(
            f"tls_enabled but certificate files are missing: "
            f"{cfg.cert_file} / {cfg.key_file}"
        )
    import uvicorn

    store = EventStore(cfg, node_map)
    store.open()
    app = create_collector_app(cfg, store)
    options: dict[str, Any] = {
        "app": app,
        "host": args.host if args.host is not None else cfg.host,
        "port": args.port if args.port is not None else cfg.port,
        "log_level": "info",
        "log_config": {"version": 1, "disable_existing_loggers": False},
        "access_log": False,
        "server_header": False,
        "proxy_headers": False,
    }
    if cfg.tls_enabled:
        options["ssl_certfile"] = str(cfg.cert_file)
        options["ssl_keyfile"] = str(cfg.key_file)
    uvicorn.run(**options)
    return 0


def ioc_command(cfg: CollectConfig, node_map: dict[str, str], args: argparse.Namespace) -> int:
    from .ioc import export_day

    if not _check_day_format(args.day):
        print(f"phptopwn-collect: --day must be YYYYMMDD, got '{args.day}'", file=sys.stderr)
        return 2
    store = EventStore(cfg, node_map)
    store.open()
    if not (store.raw_dir / f"{args.day}.jsonl").exists():
        print(f"phptopwn-collect: no raw day file for {args.day}", file=sys.stderr)
        return 2
    report = export_day(store, args.day, args.out, force=args.force)
    if report["status"] == "refused":
        print(
            "phptopwn-collect: artefacts already exist for "
            f"{args.day} (use --force): {', '.join(report['refused'])}",
            file=sys.stderr,
        )
        return 1
    counts = report["counts"]
    print(
        f"ioc export day={args.day} ips={counts['ips']} "
        f"payload_hashes={counts['payload_hashes']} out={args.out}"
    )
    for name in report["files"]:
        print(f"  wrote {name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cfg, node_map = read_collect_config(args.config)
    except CollectConfigError as exc:
        print(f"phptopwn-collect: invalid configuration: {exc}", file=sys.stderr)
        return 2
    try:
        if args.command == "serve":
            return serve_command(cfg, node_map, args)
        return ioc_command(cfg, node_map, args)
    except MissingCertificate as exc:
        print(f"phptopwn-collect: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
