"""Deception surface: the FastAPI application serving the fake file portal."""
from __future__ import annotations

import logging
from datetime import UTC, datetime

from fastapi import FastAPI, Request
from fastapi.responses import Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from .capture import Analysis, RequestCapture
from .config import Config
from .middleware import TelemetryMiddleware
from .pages import (
    LOGIN_FAILED_PAGE,
    SERVER_STATUS_PAGE,
    SESSION_UPLOAD_PAGE,
    TIMEOUT_PAGE,
    UPLOADS_PAGE,
    WP_LOGIN_PAGE,
    index_page,
    method_not_allowed_page,
    not_found_page,
    oom_page,
    php_fatal_page,
    phpinfo_page,
    upload_success_page,
)
from .runtime import Sensor

LOG = logging.getLogger("phptopwn.decoy")


def _capture(request: Request) -> RequestCapture | None:
    return request.scope.get("phptopwn.capture")


def _html_response(request: Request, cfg: Config, body: str, status: int = 200) -> Response:
    capture = _capture(request)
    if capture is not None and capture.timed_out:
        status = 408
        body = TIMEOUT_PAGE
    payload = body.encode("utf-8")
    headers = {
        "Content-Type": "text/html; charset=UTF-8",
        "Content-Length": str(len(payload)),
        "Accept-Ranges": "bytes",
    }
    if request.method == "HEAD":
        return Response(status_code=status, headers=headers)
    return Response(content=payload, status_code=status, headers=headers)


def create_app(cfg: Config, sensor: Sensor) -> FastAPI:
    decoy = cfg.decoy

    def upload_response(request: Request) -> Response:
        capture = _capture(request)
        analysis = (capture.analysis if capture else Analysis()) or Analysis()

        if "CVE-2026-109618" in analysis.cves:
            return _html_response(request, cfg, oom_page(decoy), status=500)
        if "CVE-2026-109619" in analysis.cves:
            return _html_response(request, cfg, SESSION_UPLOAD_PAGE, status=200)

        filename = ""
        if capture and capture.multipart and capture.multipart.file_parts:
            filename = capture.multipart.file_parts[0].filename or ""
        return _html_response(request, cfg, upload_success_page(filename), status=200)

    app = FastAPI(title="Acme Intranet", docs_url=None, redoc_url=None, openapi_url=None, debug=False)
    app.add_middleware(TelemetryMiddleware, cfg=cfg, sensor=sensor)

    @app.api_route("/", methods=["GET", "HEAD"])
    @app.api_route("/index.php", methods=["GET", "HEAD"])
    @app.api_route("/index.html", methods=["GET", "HEAD"])
    async def index(request: Request) -> Response:
        return _html_response(request, cfg, index_page(decoy, cfg.sensor.http_port))

    @app.api_route("/phpinfo.php", methods=["GET", "HEAD"])
    async def phpinfo(request: Request) -> Response:
        return _html_response(request, cfg, phpinfo_page(decoy))

    @app.api_route("/uploads", methods=["GET", "HEAD"])
    @app.api_route("/uploads/", methods=["GET", "HEAD"])
    async def uploads(request: Request) -> Response:
        return _html_response(request, cfg, UPLOADS_PAGE)

    @app.api_route("/server-status", methods=["GET", "HEAD"])
    async def server_status(request: Request) -> Response:
        timestamp = datetime.now(UTC).strftime("%a %b %d %H:%M:%S %Y")
        page = (
            SERVER_STATUS_PAGE.format(server_token=decoy.server_token)
            .replace("__TIME__", timestamp)
            .replace("__SCOREBOARD__", "_" * 120)
        )
        return _html_response(request, cfg, page)

    @app.api_route("/upload.php", methods=["POST", "PUT", "PATCH"])
    async def upload_endpoint(request: Request) -> Response:
        return upload_response(request)

    @app.api_route("/wp-login.php", methods=["GET", "HEAD", "POST"])
    async def wp_login(request: Request) -> Response:
        if request.method == "POST":
            return _html_response(request, cfg, LOGIN_FAILED_PAGE, status=200)
        return _html_response(request, cfg, WP_LOGIN_PAGE)

    @app.api_route("/robots.txt", methods=["GET", "HEAD"])
    async def robots(request: Request) -> Response:
        return Response(
            content="User-agent: *\nDisallow: /uploads/\nDisallow: /admin/\n",
            media_type="text/plain",
        )

    @app.api_route(
        "/{full_path:path}",
        methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"],
    )
    async def catch_all(request: Request, full_path: str) -> Response:
        capture = _capture(request)
        method = request.method.upper()
        path = "/" + full_path

        if method == "OPTIONS":
            return Response(
                status_code=200,
                headers={
                    "Allow": "GET,HEAD,POST,PUT,DELETE,OPTIONS,TRACE",
                    "Content-Length": "0",
                },
            )
        if method == "TRACE":
            return _html_response(request, cfg, method_not_allowed_page(method), status=405)
        if method == "DELETE":
            return _html_response(request, cfg, not_found_page(decoy, path), status=404)
        if method in {"POST", "PUT", "PATCH"}:
            is_php = path.endswith((".php", ".phtml", ".php5", ".php7"))
            if is_php or (capture and (capture.multipart or capture.form)):
                return upload_response(request)
        return _html_response(request, cfg, not_found_page(decoy, path), status=404)

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> Response:
        if exc.status_code == 404:
            return _html_response(request, cfg, not_found_page(decoy, request.url.path), 404)
        if exc.status_code == 405:
            return _html_response(request, cfg, method_not_allowed_page(request.method), 405)
        return _html_response(
            request,
            cfg,
            f"<h1>{exc.status_code} {exc.detail}</h1>",
            exc.status_code,
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> Response:
        LOG.exception("unhandled decoy exception: %s", exc)
        return _html_response(request, cfg, php_fatal_page(decoy), status=500)

    return app
