"""Daily IOC export: attacker IPs and payload hashes from one collector day.

The export is operator-invoked: ``phptopwn-collect ioc --day YYYYMMDD``. It
scans the raw day file once, aggregates per-IP and per-payload-hash activity
and writes JSON + CSV artefacts plus a SHA-256 manifest so later consumers
can verify integrity. Nothing is sent anywhere.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .collector import EventStore, utc_now

_PAYLOAD_KINDS = {"request_body", "uploaded_file", "payload_fragment"}


@dataclass
class _Entity:
    first_seen: str = ""
    last_seen: str = ""
    events: int = 0
    exploits: int = 0
    regions: set[str] = field(default_factory=set)
    nodes: set[str] = field(default_factory=set)

    def observe(
        self,
        timestamp: str,
        is_exploit: bool,
        region: str,
        node: str,
    ) -> None:
        if not self.first_seen or timestamp < self.first_seen:
            self.first_seen = timestamp
        if not self.last_seen or timestamp > self.last_seen:
            self.last_seen = timestamp
        self.events += 1
        self.exploits += 1 if is_exploit else 0
        self.regions.add(region)
        self.nodes.add(node)

    def to_json(self, value: str) -> dict[str, Any]:
        return {
            "value": value,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "events": self.events,
            "exploits": self.exploits,
            "regions": sorted(self.regions),
            "nodes": sorted(self.nodes),
        }


def aggregate_day(store: EventStore, day: str) -> dict[str, Any]:
    """Aggregate one raw day file into IP and payload-hash summaries."""
    ips: dict[str, _Entity] = {}
    payloads: dict[str, _Entity] = {}
    event_count = 0
    exploit_count = 0
    for record in store.iter_day(day):
        event_count += 1
        analysis = record.get("analysis") or {}
        is_exploit = bool(analysis.get("is_exploit"))
        exploit_count += 1 if is_exploit else 0
        timestamp = str(record.get("timestamp") or "")
        metarec = record.get("collector") or {}
        region = str(metarec.get("region", "unknown"))
        node = str(metarec.get("node", "unknown"))
        client = record.get("client") or {}
        ip = client.get("ip")
        if isinstance(ip, str) and ip:
            entity = ips.setdefault(ip, _Entity())
            entity.observe(timestamp, is_exploit, region, node)
        for value, _hash_entity in _payload_hashes(record):
            target = payloads.setdefault(value, _Entity())
            target.observe(timestamp, is_exploit, region, node)
    return {
        "schema": "phptopwn.ioc/1.0",
        "day": day,
        "generated_at": utc_now(),
        "generator": "phptopwn-collect",
        "totals": {"events": event_count, "exploits": exploit_count},
        "ips": [
            ips[value].to_json(value) for value in sorted(ips, key=lambda v: (-ips[v].events, v))
        ],
        "payload_hashes": [
            payloads[value].to_json(value)
            for value in sorted(payloads, key=lambda v: (-payloads[v].events, v))
        ],
    }


def _payload_hashes(record: dict[str, Any]) -> list[tuple[str, str]]:
    """All payload hashes worth exporting: body digest plus quarantined parts."""
    results: list[tuple[str, str]] = []
    body = record.get("body") or {}
    body_hash = body.get("sha256")
    if isinstance(body_hash, str) and len(body_hash) == 64 and body.get("bytes", 0) > 0:
        results.append((body_hash, "request_body"))
    for artifact in record.get("artifacts") or []:
        hash_value = artifact.get("sha256")
        kind = artifact.get("kind")
        if isinstance(hash_value, str) and len(hash_value) == 64 and kind in _PAYLOAD_KINDS:
            results.append((hash_value, str(kind)))
    return results


def export_day(
    store: EventStore, day: str, out_dir: Path, force: bool = False
) -> dict[str, Any]:
    """Write the JSON, CSV and manifest artefacts for one day.

    Returns a report dict with the file paths and entity counts.
    """
    aggregate = aggregate_day(store, day)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"ioc-{day}.json"
    csv_path = out_dir / f"ioc-{day}.csv"
    manifest_path = out_dir / f"ioc-{day}.manifest.json"
    existing = [path for path in (json_path, csv_path, manifest_path) if path.exists()]
    if existing and not force:
        return {
            "day": day,
            "status": "refused",
            "refused": [str(path) for path in existing],
        }

    json_path.write_text(
        json.dumps(aggregate, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    csv_path.write_text(_csv_text(aggregate), encoding="utf-8")
    manifest = {
        "schema": "phptopwn.ioc-manifest/1.0",
        "day": day,
        "generated_at": utc_now(),
        "files": {
            json_path.name: _sha256_file(json_path),
            csv_path.name: _sha256_file(csv_path),
        },
        "totals": aggregate["totals"],
        "counts": {
            "ips": len(aggregate["ips"]),
            "payload_hashes": len(aggregate["payload_hashes"]),
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return {
        "day": day,
        "status": "exported",
        "files": [str(json_path), str(csv_path), str(manifest_path)],
        "counts": manifest["counts"],
        "totals": manifest["totals"],
    }


_CSV_HEADER = "type,value,first_seen,last_seen,events,exploits,regions"


def _csv_text(aggregate: dict[str, Any]) -> str:
    lines = [_CSV_HEADER]
    for entry in aggregate["ips"]:
        lines.append(_csv_line("ip", entry))
    for entry in aggregate["payload_hashes"]:
        kind = "payload_hash"
        lines.append(_csv_line(kind, entry))
    return "\n".join(lines) + "\n"


def _csv_line(kind: str, entry: dict[str, Any]) -> str:
    regions = "|".join(entry["regions"])
    fields_out = (
        kind,
        entry["value"],
        entry["first_seen"],
        entry["last_seen"],
        str(entry["events"]),
        str(entry["exploits"]),
        regions,
    )
    return ",".join(_csv_field(value) for value in fields_out)


def _csv_field(value: str) -> str:
    if any(char in value for char in (",", '"', "\n", "\r")):
        return '"' + value.replace('"', '""') + '"'
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()
