"""ASGI middleware: bounded body capture, analysis, telemetry persistence."""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .capture import BodySpool, RequestCapture
from .config import Config
from .detection import analyze
from .pages import BAD_HEADER_PAGE, FORBIDDEN_PAGE, php_fatal_page
from .parsing import enrich_capture
from .runtime import Sensor
from .storage import utc_now

LOG = logging.getLogger("phptopwn.middleware")


def peer_ip(scope: Scope) -> str:
    client = scope.get("client") or ("0.0.0.0", 0)
    return str(client[0]) if client else "0.0.0.0"


def headers_overflow(scope: Scope, limits: Any) -> bool:
    headers = scope.get("headers", [])
    if len(headers) > limits.max_request_headers:
        return True
    total = sum(len(name) + len(value) + 4 for name, value in headers[:2048])
    return total > limits.max_header_bytes


class TelemetryMiddleware:
    def __init__(self, app: ASGIApp, cfg: Config, sensor: Sensor) -> None:
        self.app = app
        self.cfg = cfg
        self.sensor = sensor

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        ip = peer_ip(scope)
        reason = self.sensor.guard.acquire(ip)
        if reason:
            await self._reject(scope, send, ip, reason)
            self.sensor.guard.release(ip)
            return

        if headers_overflow(scope, self.cfg.limits):
            await self._reject(scope, send, ip, "header_flood")
            self.sensor.guard.release(ip)
            return

        try:
            try:
                capture = await self._read_request(scope, receive)
            except Exception:
                LOG.exception("failed while reading request body")
                await self._send_fatal(send)
                return

            await self._classify(capture)
            scope["phptopwn.capture"] = capture
            replay_state = {"finished": False}

            async def replay() -> Message:
                chunk = capture.body.read_replay_chunk()
                if chunk:
                    return {"type": "http.request", "body": chunk, "more_body": True}
                if not replay_state["finished"]:
                    replay_state["finished"] = True
                    return {"type": "http.request", "body": b"", "more_body": False}
                return {"type": "http.disconnect"}

            async def send_wrapper(message: Message) -> None:
                if message["type"] == "http.response.start":
                    capture.response_started = True
                    capture.status_code = int(message["status"])
                    headers = MutableHeaders(scope=message)
                    headers["Server"] = self.cfg.decoy.server_token
                    headers["X-Powered-By"] = self.cfg.decoy.powered_by
                    headers["X-Request-Id"] = capture.request_id
                    if capture.body.truncated or capture.incomplete:
                        headers["Connection"] = "close"
                    capture.response_headers = dict(headers)
                await send(message)

            try:
                await self.app(scope, replay, send_wrapper)
            except Exception as exc:  # keep the illusion of an Apache/PHP 500
                capture.error = f"{type(exc).__name__}: {exc}"[:2000]
                LOG.exception("decoy handler failed for %s", capture.request_id)
                if not capture.response_started:
                    try:
                        await send_wrapper(
                            {
                                "type": "http.response.start",
                                "status": 500,
                                "headers": [(b"content-type", b"text/html; charset=UTF-8")],
                            }
                        )
                        await send_wrapper(
                            {"type": "http.response.body", "body": php_fatal_page(self.cfg.decoy).encode()}
                        )
                    except Exception:
                        LOG.debug("client disconnected before the 500 response", exc_info=True)
            finally:
                self.sensor.metrics.observe_capture(capture)
                await self.sensor.store.persist(capture)
                self.sensor.alerts.maybe_dispatch(capture)
        finally:
            self.sensor.guard.release(ip)

    async def _reject(self, scope: Scope, send: Send, ip: str, reason: str) -> None:
        """Refuse abusive requests without draining the body."""
        status, page = 403, FORBIDDEN_PAGE
        if reason == "header_flood":
            status, page = 400, BAD_HEADER_PAGE
        capture = self._guard_capture(scope, ip, reason)
        try:
            await send(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [
                        (b"content-type", b"text/html; charset=UTF-8"),
                        (b"server", self.cfg.decoy.server_token.encode()),
                        (b"x-request-id", capture.request_id.encode()),
                        (b"connection", b"close"),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": page.encode()})
            capture.status_code = status
            self.sensor.metrics.observe_guard(reason, ip)
            await self.sensor.store.persist(capture)
        except Exception:  # pragma: no cover - peer gone mid-reject
            capture.body.close()

    def _guard_capture(self, scope: Scope, ip: str, reason: str) -> RequestCapture:
        headers_raw = [
            (name.decode("latin-1", "replace")[:256], value.decode("latin-1", "replace")[:4096])
            for name, value in scope.get("headers", [])[: self.cfg.limits.max_request_headers]
        ]
        client = scope.get("client") or ("0.0.0.0", 0)
        capture = RequestCapture(
            request_id=uuid.uuid4().hex,
            timestamp=utc_now(),
            tls=scope.get("scheme") == "https",
            method=scope.get("method", "GET")[:16],
            scheme=scope.get("scheme", "http"),
            host="",
            path=scope.get("path", "/")[:2048],
            raw_path="",
            query=scope.get("query_string", b"").decode("latin-1", "replace")[:8192],
            http_version=scope.get("http_version", "1.1"),
            client_ip=ip,
            client_port=client[1] if len(client) > 1 else None,
            headers=headers_raw,
            header_map={},
            header_count=0,
            header_bytes=0,
            duplicate_headers=0,
            declared_content_length=None,
            transfer_encoding="",
            body=BodySpool(self.cfg.storage.max_body_bytes),
        )
        capture.error = reason
        return capture

    async def _classify(self, capture: RequestCapture) -> None:
        await asyncio.to_thread(self._analyze, capture)

    def _analyze(self, capture: RequestCapture) -> None:
        enrich_capture(capture)
        capture.analysis = analyze(capture, self.cfg)

    async def _send_fatal(self, send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 500,
                "headers": [
                    (b"content-type", b"text/html; charset=UTF-8"),
                    (b"server", self.cfg.decoy.server_token.encode()),
                ],
            }
        )
        await send(
            {"type": "http.response.body", "body": php_fatal_page(self.cfg.decoy).encode()}
        )

    async def _read_request(self, scope: Scope, receive: Receive) -> RequestCapture:
        cfg = self.cfg
        headers_raw = [
            (name.decode("latin-1", "replace"), value.decode("latin-1", "replace"))
            for name, value in scope.get("headers", [])
        ]
        header_map: dict[str, str] = {}
        counts: dict[str, int] = {}
        header_bytes = 0
        for name, value in headers_raw:
            key = name.lower()
            header_map[key] = f"{header_map[key]}, {value}" if key in header_map else value
            counts[key] = counts.get(key, 0) + 1
            header_bytes += len(name) + len(value) + 4
        duplicate_headers = sum(max(0, count - 1) for count in counts.values())

        declared: int | None = None
        raw_length = header_map.get("content-length", "").strip()
        if raw_length.isdigit():
            declared = int(raw_length)

        client = scope.get("client") or ("0.0.0.0", 0)
        client_ip = str(client[0]) if client else "0.0.0.0"
        client_port = client[1] if len(client) > 1 else None
        if cfg.sensor.trust_proxy_headers:
            forwarded = header_map.get("x-forwarded-for", "")
            if forwarded:
                client_ip = forwarded.split(",")[0].strip()[:64]

        raw_path = scope.get("raw_path") or b""
        if isinstance(raw_path, bytes):
            raw_path_text = raw_path.decode("latin-1", "replace")
        else:  # pragma: no cover - ASGI spec says bytes
            raw_path_text = str(raw_path)

        capture = RequestCapture(
            request_id=uuid.uuid4().hex,
            timestamp=utc_now(),
            tls=scope.get("scheme") == "https",
            method=scope.get("method", "GET"),
            scheme=scope.get("scheme", "http"),
            host=header_map.get("host", "")[:255],
            path=scope.get("path", "/")[:2048],
            raw_path=raw_path_text[:2048],
            query=scope.get("query_string", b"").decode("latin-1", "replace")[:8192],
            http_version=scope.get("http_version", "1.1"),
            client_ip=client_ip,
            client_port=client_port,
            headers=headers_raw,
            header_map=header_map,
            header_count=len(headers_raw),
            header_bytes=header_bytes,
            duplicate_headers=duplicate_headers,
            declared_content_length=declared,
            transfer_encoding=header_map.get("transfer-encoding", ""),
            body=BodySpool(cfg.storage.max_body_bytes),
        )
        await self._drain_body(capture, receive)
        return capture

    async def _drain_body(self, capture: RequestCapture, receive: Receive) -> None:
        """Stream the request body into the bounded spool, timing each chunk."""
        timeout = self.cfg.storage.body_timeout_seconds
        probe_limit = self.cfg.storage.probe_bytes
        started = time.monotonic()
        last_chunk_at: float | None = None

        while True:
            try:
                message = await asyncio.wait_for(receive(), timeout=timeout)
            except TimeoutError:
                capture.timed_out = True
                capture.incomplete = True
                break
            except Exception:
                capture.incomplete = True
                break

            if message.get("type") == "http.disconnect":
                capture.disconnected = True
                capture.incomplete = True
                break

            chunk = message.get("body", b"")
            now = time.monotonic()
            if chunk:
                if last_chunk_at is None:
                    capture.first_byte_seconds = now - started
                elif len(capture.chunk_gaps) < 2000:
                    capture.chunk_gaps.append(round(now - last_chunk_at, 4))
                last_chunk_at = now
                capture.chunk_count += 1
                capture.body.write(chunk, probe_limit)

            if not message.get("more_body", False):
                break
            if capture.body.truncated:
                capture.incomplete = True
                break

        capture.body_seconds = time.monotonic() - started
        if (
            capture.declared_content_length is not None
            and capture.body_size < capture.declared_content_length
            and not capture.body.truncated
        ):
            capture.incomplete = True
