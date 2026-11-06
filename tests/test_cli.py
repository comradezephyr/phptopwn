"""CLI parsing, dry-run mode and config failure exits."""
from __future__ import annotations

import pytest

from phptopwn import __version__
from phptopwn.cli import build_parser, main


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["--version"])
    assert exit_info.value.code == 0
    assert f"phptopwn {__version__}" in capsys.readouterr().out


def test_parser_defaults():
    args = build_parser().parse_args([])
    assert args.config is None
    assert args.host is None and args.port is None
    assert args.dry_run is False


def test_dry_run(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "phptopwn dry run" in out
    assert "listener:" in out


def test_dry_run_with_cli_overrides(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["--dry-run", "--host", "10.0.0.9", "--port", "9101"]) == 0
    out = capsys.readouterr().out
    assert "10.0.0.9:9101" in out


def test_invalid_config_exit_code(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    broken = tmp_path / "broken.toml"
    broken.write_text("[nope]\nunknown_key = 1\n")
    assert main(["--dry-run", "--config", str(broken)]) == 2
    assert "invalid configuration" in capsys.readouterr().err


def test_missing_config_exit_code(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["--dry-run", "--config", str(tmp_path / "absent.toml")]) == 2
