#!/usr/bin/env python3
"""In-network driver for the laptop compose stack (scripts/e2e_laptop.py runs it).

Runs inside the "fleet" network attached to the sensor/collector. Stdlib only —
the deployed image ships no third-party HTTP client anyway. Each mode prints a
JSON summary line to stdout; non-zero exit means the phase failed.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import socket
import sys
import urllib.error
import urllib.request

DECODER = {}


def http_post(
    base: str, path: str, data: bytes, headers: dict[str, str], timeout: float = 20.0
) -> tuple[int, str]:
    request = urllib.request.Request(
        base.rstrip("/") + path, data=data, method="POST", headers=headers
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        return 0, f"transport:{type(exc).__name__}"


def multipart(payload_marker: str, parts: int = 34, part_kb: int = 1) -> tuple[bytes, str]:
    boundary = "----e2edriver7d3"
    chunk = "A" * (part_kb * 1024)
    pieces: list[bytes] = []
    for index in range(parts):
        field = f"chunk{index}"
        value = chunk if index else f"{chunk}{payload_marker}"
        pieces.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{field}"\r\n\r\n'
                f"{value}\r\n"
            ).encode()
        )
    pieces.append(f"--{boundary}--\r\n".encode())
    return b"".join(pieces), f"multipart/form-data; boundary={boundary}"


def mode_traffic(args: argparse.Namespace) -> int:
    base = args.base
    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Firefox/137.0"}
    results = {"sent": 0, "ok": [], "other": {}}
    futures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        for index in range(args.count):
            seq = args.seq_start + index
            body, ctype = multipart(f"e2eseq-{seq}")
            futures.append(
                (seq, pool.submit(http_post, base, "/upload.php", body, {**headers, "Content-Type": ctype}))
            )
        for seq, future in futures:
            status, _ = future.result()
            results["sent"] += 1
            if status:  # any HTTP answer counts: the decoy may serve 200 or a PHP-fatal 5xx
                results["ok"].append(seq)
            else:
                results["other"]["transport"] = results["other"].get("transport", 0) + 1
    print(json.dumps({"mode": "traffic", "first": args.seq_start, "last": args.seq_start + args.count - 1, **results}))
    return 0


def mode_oversize(args: argparse.Namespace) -> int:
    body = b"A" * (10 * 1024 * 1024)
    status, _ = http_post(
        args.base, "/upload.php", body, {"Content-Type": "application/octet-stream"}
    )
    # any HTTP answer (even a decoy 404) proves the sensor stayed responsive
    probe_status, _ = http_post(args.base, "/healthz", b"", {})
    print(
        json.dumps(
            {
                "mode": "oversize",
                "status": status,
                "sensor_responsive": probe_status != 0,
            }
        )
    )
    return 0


def mode_storm(args: argparse.Namespace) -> int:
    counts: dict[str, int] = {}

    def fire(index: int) -> int:
        body, ctype = multipart(f"e2eseq-{100000 + index}", parts=4, part_kb=1)
        status, _ = http_post(args.base, "/upload.php", body, {"Content-Type": ctype})
        return status

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for status in pool.map(fire, range(args.count)):
            counts[str(status)] = counts.get(str(status), 0) + 1
    print(json.dumps({"mode": "storm", "counts": counts}))
    return 0 if counts.get("200", 0) > 0 else 1


def mode_fuzz(args: argparse.Namespace) -> int:
    host, port = args.base.split("//")[-1].split(":")
    sloppy = [
        b"GET /index.php?x=" + b"A" * 9000 + b" HTTP/1.1\r\nHost: d\r\n\r\n",
        b"POST /upload.php HTTP/1.1\r\nHost: d\r\nContent-Length: 99\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"POST /upload.php HTTP/1.1\r\nHost: d\r\nContent-Type: multipart/form-data; boundary=b\r\n\r\n--b\r\nNoEnd",
        bytes(range(60, 120)) * 40,  # raw garbage bytes
        b"\x00\x01\x02" + b"\xff\xfe" * 300,
    ]
    outcomes = []
    for index in range(args.count):
        payload = sloppy[index % len(sloppy)]
        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                sock.sendall(payload)
                sock.settimeout(3)
                try:
                    sock.recv(2048)
                except (TimeoutError, OSError):
                    pass
            outcomes.append("ok")
        except OSError as exc:
            outcomes.append(f"err:{type(exc).__name__}")
    print(json.dumps({"mode": "fuzz", "outcomes": outcomes}))
    return 0


def mode_fingerprint(args: argparse.Namespace) -> int:
    request = urllib.request.Request(args.base + "/", method="GET")
    with urllib.request.urlopen(request, timeout=10) as response:
        page = response.read(65536).decode("utf-8", "replace")
        server = response.headers.get("Server", "")
    probe = urllib.request.Request(args.base + "/phpinfo.php", method="GET")
    with urllib.request.urlopen(probe, timeout=10) as response:
        powered_by = response.headers.get("X-Powered-By", "")
    ok = bool(server) and bool(powered_by) and "Intranet File Portal" in page
    print(
        json.dumps(
            {
                "mode": "fingerprint",
                "server": server,
                "powered_by": powered_by,
                "index_ok": ok,
            }
        )
    )
    return 0 if ok else 1


def mode_probe(args: argparse.Namespace) -> int:
    """TCP reachability probe: exit 0 when reachable, 3 when not."""
    try:
        with socket.create_connection((args.host, args.port), timeout=float(args.timeout)):
            print(json.dumps({"mode": "probe", "host": args.host, "port": args.port, "reachable": True}))
            return 0
    except OSError as exc:
        print(
            json.dumps(
                {"mode": "probe", "host": args.host, "port": args.port, "reachable": False, "error": str(exc)}
            )
        )
        return 3


def mode_replay(args: argparse.Namespace) -> int:
    """Resend captured request_ids straight to the collector to prove dedupe."""
    ids_path = "/sensor-logs/exploits.json"
    with open(ids_path, encoding="utf-8") as handle:
        lines = [line for line in handle if line.strip()]
    wanted = [(json.loads(line), index) for index, line in enumerate(lines[-args.count :])]
    records = []
    for source, index in wanted:
        records.append(
            {
                "schema": "phptopwn.event/1.0",
                "event": "http_request",
                "request_id": source["request_id"],
                "timestamp": source["timestamp"],
                "client": {"ip": source.get("client", {}).get("ip", "192.0.2.1"), "peer_ip": "192.0.2.1"},
                "request": {"method": "POST", "path": "/upload.php"},
                "marked": f"replay{index}",
            }
        )
    payload = "\n".join(json.dumps(record) for record in records) + "\n"
    status, text = http_post(
        "http://collector:9443", "/v1/events", payload.encode(),
        {
            "Content-Type": "application/x-ndjson",
            "Authorization": f"Bearer {args.token}",
            "X-Phptopwn-Node": args.node,
        },
    )
    print(json.dumps({"mode": "replay", "count": len(records), "http": status, "body": text[:400]}))
    return 0 if status == 200 else 1


def main() -> int:
    parser = argparse.ArgumentParser(prog="e2e-driver")
    parser.add_argument("--base", default="http://sensor:8080", help="sensor http base URL")
    sub = parser.add_subparsers(dest="mode", required=True)

    traffic = sub.add_parser("traffic")
    traffic.add_argument("--count", type=int, default=40)
    traffic.add_argument("--seq-start", type=int, default=0)
    traffic.add_argument("--concurrency", type=int, default=4)
    traffic.set_defaults(func=mode_traffic)

    oversize = sub.add_parser("oversize")
    oversize.set_defaults(func=mode_oversize)

    storm = sub.add_parser("storm")
    storm.add_argument("--count", type=int, default=60)
    storm.set_defaults(func=mode_storm)

    fuzz = sub.add_parser("fuzz")
    fuzz.add_argument("--count", type=int, default=20)
    fuzz.set_defaults(func=mode_fuzz)

    fingerprint = sub.add_parser("fingerprint")
    fingerprint.set_defaults(func=mode_fingerprint)

    probe = sub.add_parser("probe")
    probe.add_argument("--host", required=True)
    probe.add_argument("--port", type=int, required=True)
    probe.add_argument("--timeout", default=3)
    probe.set_defaults(func=mode_probe)

    replay = sub.add_parser("replay")
    replay.add_argument("--count", type=int, default=5)
    replay.add_argument("--token", required=True)
    replay.add_argument("--node", required=True)
    replay.set_defaults(func=mode_replay)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
