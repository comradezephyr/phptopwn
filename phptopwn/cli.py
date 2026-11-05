"""Command line interface."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import ConfigError, dry_run_report, load_config
from .server import MissingCertificate, serve, setup_logging

_DESCRIPTION = "High-interaction HTTP honeypot sensor for PHP2Shell exploitation attempts."


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phptopwn", description=_DESCRIPTION)
    parser.add_argument(
        "--version", action="version", version=f"phptopwn {__version__}"
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="path to a TOML config file (default: ./phptopwn.toml if present)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the resolved configuration, validate it, and exit",
    )
    parser.add_argument("--host", default=None, help="override the bind address")
    parser.add_argument("--port", type=int, default=None, help="override the HTTP port")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cfg = load_config(
            args.config,
            overrides={"host": args.host, "http_port": args.port},
        )
    except ConfigError as exc:
        print(f"phptopwn: invalid configuration: {exc}", file=sys.stderr)
        return 2

    if args.dry_run:
        source = str(args.config) if args.config else "built-in defaults (./phptopwn.toml if present)"
        print(dry_run_report(cfg, source))
        return 0

    setup_logging(cfg)
    try:
        serve(cfg)
    except MissingCertificate as exc:
        print(f"phptopwn: {exc}", file=sys.stderr)
        return 2
    except ConfigError as exc:
        print(f"phptopwn: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
