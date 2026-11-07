#!/usr/bin/env python3
"""End-to-end verification for the laptop compose stack (docs/DEPLOY-LAPTOP.md).

Run after `cp .env.example .env` and filling the values. The script brings the
stack up itself (sensor + collector + e2e helpers; the cloudflared profile is
only included when TUNNEL_TOKEN is set). Every phase prints ok/FAIL evidence;
the script stops at the first failure and exits non-zero.

Phases:
  1. preflight:   storm, oversize body, fuzz, fingerprint.
  2. capture:     driver -> sensor -> outbox -> forwarder -> collector /data.
  3. resume:      SIGKILL the sensor mid-run, restart, byte-offset resume;
                  exact line count + unique request_ids (no gaps, no dupes).
  4. restart:     full stack restart -> volume persistence + replay dedupe.
  5. ioc export:  phptopwn-collect ioc -> JSON + CSV + manifest re-verified
                  (sha256 recomputation + non-empty counts) inside the
                  collector container.
  6. isolation:   no published ports, internal network flag, probe container
                  on the regular bridge network cannot reach sensor or
                  collector (the tunnel is the only path in).
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROJECT = "php2shell-laptop"

# Inside-container verification for phase 5: recompute manifest hashes and
# assert both IOC kinds are populated. Piped to `exec collector python -`.
VERIFY_IOC = """
import hashlib, json, pathlib, sys
out = pathlib.Path("/data/ioc-exports")
day = sys.argv[1]
paths = {
    name: out / f"ioc-{day}.{ext}"
    for name, ext in (("json", "json"), ("csv", "csv"), ("manifest", "manifest.json"))
}
missing = [name for name, path in paths.items() if not path.exists()]
if missing:
    print(f"VERIFY FAILED missing artefacts: {missing}")
    sys.exit(1)

def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()

manifest = json.loads(paths["manifest"].read_text(encoding="utf-8"))
ok = True
for name in (f"ioc-{day}.json", f"ioc-{day}.csv"):
    expected = manifest["files"].get(name)
    actual = sha256(out / name)
    if expected != actual:
        print(f"VERIFY FAILED {name}: manifest={expected} actual={actual}")
        ok = False
counts = manifest["counts"]
aggregate = json.loads(paths["json"].read_text(encoding="utf-8"))
csv_rows = len(paths["csv"].read_text(encoding="utf-8").splitlines()) - 1
if counts["ips"] < 1 or not aggregate["ips"]:
    print("VERIFY FAILED: no IOC ips aggregated")
    ok = False
if counts["payload_hashes"] < 1 or not aggregate["payload_hashes"]:
    print("VERIFY FAILED: no payload hashes aggregated")
    ok = False
if csv_rows < 1:
    print("VERIFY FAILED: csv has no data rows")
    ok = False
print(
    f"VERIFY {'OK' if ok else 'FAILED'} ips={counts['ips']} "
    f"payload_hashes={counts['payload_hashes']} csv_rows={csv_rows}"
)
sys.exit(0 if ok else 1)
"""

# Inside-container verification for phase 3: every raw line parses and all
# request_ids are unique (no duplicate shipment after the resume).
ASSERT_UNIQ = """
import json, pathlib, sys
day = pathlib.Path(sys.argv[1])
ids: list[str] = []
for line in day.open(encoding="utf-8"):
    record = json.loads(line)
    ids.append(record["request_id"])
dupes = len(ids) - len(set(ids))
print(f"UNIQ {'OK' if dupes == 0 else 'FAILED'} lines={len(ids)} duplicates={dupes}")
sys.exit(0 if dupes == 0 else 1)
"""


def env_of_dotenv() -> dict[str, str]:
    values: dict[str, str] = {}
    path = REPO / ".env"
    if not path.exists():
        print("FAIL: .env missing — copy .env.example to .env and fill the values first")
        raise SystemExit(1)
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


ENV = env_of_dotenv()
FLEET_TOKEN = ENV.get("FLEET_TOKEN", "")
NODE_ID = ENV.get("NODE_ID", "")
TUNNEL_TOKEN = ENV.get("TUNNEL_TOKEN", "")
if not FLEET_TOKEN or not NODE_ID:
    print("FAIL: .env must set FLEET_TOKEN and NODE_ID")
    raise SystemExit(1)
WITH_TUNNEL = bool(TUNNEL_TOKEN) and "--with-tunnel" in sys.argv
PROFILES = ["e2e"] + (["tunnel"] if WITH_TUNNEL else [])


def compose(
    args: list[str], *, timeout: int = 600, input: str | None = None, check_rc: bool = True
) -> subprocess.CompletedProcess:
    argv = ["docker", "compose", "-p", PROJECT]
    for profile in PROFILES:
        argv += ["--profile", profile]
    argv += args
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, input=input)
    if check_rc and result.returncode != 0:
        print(f"FAIL: command exited {result.returncode}: {' '.join(argv)}")
        print(result.stdout[-3000:])
        print(result.stderr[-3000:])
        raise SystemExit(1)
    return result


def driver_service(
    mode: str, extra: list[str], *, timeout: int = 300, input: str | None = None
) -> subprocess.CompletedProcess:
    return compose(
        ["run", "--rm", "-T", "--entrypoint", "python", "driver", "/driver/e2e_driver.py", mode, *extra],
        timeout=timeout,
        input=input,
    )


def probe_service(mode: str, extra: list[str], *, timeout: int = 60) -> subprocess.CompletedProcess:
    # probe mode exits 3 when the target is UNREACHABLE — that is the expected
    # outcome in the isolation phase, so the return code must not fail the run.
    return compose(
        ["run", "--rm", "-T", "--entrypoint", "python", "probe", "/driver/e2e_driver.py", mode, *extra],
        timeout=timeout,
        check_rc=False,
    )


def driver_json(result: subprocess.CompletedProcess) -> dict:
    if result.returncode not in (0, 3):
        print(f"FAIL: driver mode exited {result.returncode}")
        print(result.stdout[-2000:])
        print(result.stderr[-2000:])
        raise SystemExit(1)
    return json.loads(result.stdout.strip().splitlines()[-1])


def check(condition: bool, message: str, *, hard: bool = True) -> bool:
    if condition:
        print(f"  ok: {message}")
        return True
    if hard:
        print(f"FAIL: {message}")
        raise SystemExit(1)
    print(f"  note: {message}")
    return False


def container_ip(service: str) -> str:
    """Fleet-network address of a compose service (each has exactly one)."""
    result = compose(["exec", "-T", service, "sh", "-c", "hostname -i"], timeout=60)
    addresses = result.stdout.split()
    if not addresses:
        print(f"FAIL: no address found for {service}")
        raise SystemExit(1)
    return addresses[0]


def day_path() -> str:
    return datetime.now(UTC).strftime("/data/raw/%Y%m%d.jsonl")


def raw_count(timeout: int = 60) -> int:
    result = compose(
        ["exec", "-T", "collector", "sh", "-c", f"wc -l {day_path()} 2>/dev/null; true"],
        timeout=timeout,
        check_rc=False,
    )
    tokens = result.stdout.strip().split()
    if not tokens or not tokens[0].isdigit():
        return 0
    return int(tokens[0])


def wait_for_raw(minimum: int, *, seconds: int = 150) -> int:
    deadline = time.time() + seconds
    last = raw_count()
    while time.time() < deadline:
        last = raw_count()
        if last >= minimum:
            return last
        time.sleep(1.5)
    return last


HEALTH_SNIPPET = (
    "import sys,urllib.request; "
    "sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:{port}/healthz',"
    " timeout=3).status == 200 else 1)"
)


def alive(service: str, port: int) -> bool:
    result = compose(
        ["exec", "-T", service, "python", "-c", HEALTH_SNIPPET.format(port=port)],
        timeout=30,
        check_rc=False,
    )
    return result.returncode == 0


def main() -> int:
    phase_started = time.time()

    print("\n### phase 0: bring-up")
    compose(["up", "-d", "--build"], timeout=900)
    # compose quirk: the first `run` after `up --build` may recreate the
    # dependencies; trigger that convergence on a no-op run so the traffic
    # phases never race a container restart.
    compose(["run", "--rm", "-T", "--entrypoint", "true", "driver"], timeout=180)
    deadline = time.time() + 120
    while time.time() < deadline and not (alive("sensor", 9091) and alive("collector", 9443)):
        time.sleep(2)
    check(alive("sensor", 9091), "sensor internal healthz responding")
    check(alive("collector", 9443), "collector /healthz responding")

    print("\n### phase 1: preflight (storm / fingerprint / oversize / fuzz)")
    storm = driver_json(driver_service("storm", ["--count", "60"]))
    check(storm["counts"].get("200", 0) >= 50, f"rate storm: {storm['counts']}")
    fingerprint = driver_service("fingerprint", [])
    check(fingerprint.returncode == 0, f"decoy fingerprint intact: {fingerprint.stdout.strip().splitlines()[-1]}")
    oversize = driver_json(driver_service("oversize", []))
    check(oversize["sensor_responsive"], f"10MiB oversize body handled, sensor responsive (http={oversize['status']})")
    fuzz = driver_json(driver_service("fuzz", ["--count", "20"]))
    clean = fuzz["outcomes"].count("ok")
    check(clean >= 15, f"fuzz: {clean}/20 sloppy exchanges without transport errors")
    check(alive("sensor", 9091), "sensor alive after preflight")
    check(alive("collector", 9443), "collector alive after preflight")

    print("\n### phase 2: capture — driver -> sensor -> outbox -> forwarder -> collector /data")
    phase_a = driver_json(driver_service("traffic", ["--count", "40", "--seq-start", "0", "--concurrency", "4"]))
    check(len(phase_a["ok"]) == 40, f"phase A: 40/40 requests got a decoy response (other={phase_a['other'] or '{}'})")
    reached = wait_for_raw(40)
    check(reached >= 40, f"collector raw day file reached {reached} lines (>= 40)")

    print("\n### phase 3: resume — SIGKILL sensor mid-run, byte-offset resume, no gaps, no dupes")
    phase_b = driver_json(driver_service("traffic", ["--count", "40", "--seq-start", "40", "--concurrency", "4"]))
    check(len(phase_b["ok"]) == 40, f"phase B: 40/40 requests got a decoy response (other={phase_b['other'] or '{}'})")
    before = raw_count()
    compose(["kill", "-s", "SIGKILL", "sensor"], timeout=120)
    check(not alive("sensor", 9091), "sensor SIGKILLed mid-run")
    unsynced = wait_for_raw(before + 40, seconds=8)
    if unsynced < before + 40:
        check(True, f"phase-B backlog held in the outbox (raw={unsynced}, target={before + 40})", hard=False)
    else:
        print("  note: forwarder flushed phase B before the kill; resume still verified by the exact count below")
    compose(["start", "sensor"], timeout=120)
    final = wait_for_raw(before + 40, seconds=150)
    check(
        final == before + 40,
        f"byte-offset resume: exactly {before + 40} raw lines after restart (got {final}) — no gaps",
    )
    uniq = compose(
        ["exec", "-T", "collector", "python", "-", day_path()],
        input=ASSERT_UNIQ,
        timeout=60,
        check_rc=True,
    )
    check(uniq.stdout.strip().startswith("UNIQ OK"), f"request_id uniqueness: {uniq.stdout.strip()}")

    print("\n### phase 4: full stack restart — volume persistence + collector dedupe")
    compose(["restart"], timeout=300)
    deadline = time.time() + 120
    while time.time() < deadline and not (alive("sensor", 9091) and alive("collector", 9443)):
        time.sleep(2)
    check(alive("collector", 9443), "collector healthy after stack restart")
    check(alive("sensor", 9091), "sensor healthy after stack restart")
    persisted = raw_count()
    check(
        persisted == before + 40,
        f"volume persistence: {persisted} raw lines kept across full restart (was {before + 40})",
    )
    replay = driver_json(
        driver_service(
            "replay", ["--count", "5", "--token", FLEET_TOKEN, "--node", NODE_ID],
            timeout=120,
        )
    )
    replay_body = json.loads(replay["body"])
    check(
        replay_body["duplicates"] == 5 and replay_body["accepted"] == 0,
        f"replay of 5 real request_ids deduped on the collector: {replay_body}",
    )
    check(
        raw_count() == persisted,
        f"raw line count unchanged after replay ({raw_count()} == {persisted})",
    )

    print("\n### phase 5: IOC export — phptopwn-collect ioc, JSON + CSV + manifest")
    day = datetime.now(UTC).strftime("%Y%m%d")
    export = compose(
        [
            "exec", "-T", "collector",
            "phptopwn-collect", "ioc",
            "--config", "/tmp/collect.toml",
            "--day", day, "--out", "/data/ioc-exports",
        ],
        timeout=120,
    )
    summary = export.stdout.strip().splitlines()[0] if export.stdout.strip() else ""
    check(export.returncode == 0, f"ioc export ok: {summary}")
    verify = compose(
        ["exec", "-T", "collector", "python", "-", day],
        input=VERIFY_IOC,
        timeout=120,
    )
    verified = verify.returncode == 0 and "VERIFY OK" in verify.stdout
    check(verified, f"ioc artefact verification: {verify.stdout.strip()}")

    print("\n### phase 6: isolation — no published ports; cross-network probe blocked")
    ps = compose(["ps", "--format", "json"], timeout=60)
    try:
        entries = json.loads(ps.stdout)
        if isinstance(entries, dict):
            entries = [entries]
    except json.JSONDecodeError:
        entries = [json.loads(line) for line in ps.stdout.strip().splitlines() if line.strip()]
    for entry in entries:
        name = entry.get("Service", entry.get("Name", "?"))
        if name in ("sensor", "collector"):
            check(not entry.get("Publishers"), f"{name} publishes no ports")
    inspected = subprocess.run(
        ["docker", "network", "inspect", f"{PROJECT}_fleet", "--format", "{{.Internal}}"],
        capture_output=True, text=True, timeout=60,
    )
    check(inspected.stdout.strip() == "true", "fleet network inspected: Internal=true (no NAT egress)")
    sensor_ip = container_ip("sensor")
    collector_ip = container_ip("collector")
    blocked_sensor = driver_json(probe_service("probe", ["--host", sensor_ip, "--port", "8080"]))
    blocked_collector = driver_json(probe_service("probe", ["--host", collector_ip, "--port", "9443"]))
    check(
        blocked_sensor["reachable"] is False,
        f"probe container on the bridge network cannot reach sensor {sensor_ip}:8080",
    )
    check(
        blocked_collector["reachable"] is False,
        f"probe container on the bridge network cannot reach collector {collector_ip}:9443",
    )

    print(f"\nALL PHASES PASSED in {time.time() - phase_started:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
