"""Apache/PHP decoy page templates: fingerprints and injection safety."""
from __future__ import annotations

from phptopwn.config import load_config
from phptopwn.pages import (
    BAD_HEADER_PAGE,
    FORBIDDEN_PAGE,
    TIMEOUT_PAGE,
    UPLOADS_PAGE,
    _memory_limit_bytes,
    index_page,
    method_not_allowed_page,
    not_found_page,
    oom_page,
    php_fatal_page,
    phpinfo_page,
    upload_success_page,
)

DECOY = load_config(environ={}).decoy


def test_fatal_and_timeout_pages_keep_apache_tokens():
    assert "Internal Server Error" in php_fatal_page(DECOY)
    assert "Apache/2.4.52 (Ubuntu)" in php_fatal_page(DECOY)
    assert "403 Forbidden" in FORBIDDEN_PAGE
    assert "400 Bad Request" in BAD_HEADER_PAGE
    assert "408 Request Timeout" in TIMEOUT_PAGE
    assert "Index of /uploads" in UPLOADS_PAGE


def test_oom_page_reflects_memory_limit():
    page = oom_page(DECOY)
    assert "Allowed memory size of 134217728 bytes" in page  # 128M
    assert _memory_limit_bytes("128M") == 128 * 1024 * 1024
    assert _memory_limit_bytes("1G") == 1024 * 1024 * 1024
    assert _memory_limit_bytes("512K") == 512 * 1024


def test_not_found_page_escapes_injected_paths():
    page = not_found_page(DECOY, "/drop<script>alert(1)</script>.txt")
    assert "404 Not Found" in page
    assert "<script>" not in page
    assert "&lt;script&gt;" in page


def test_method_not_allowed_page_escapes_method():
    page = method_not_allowed_page("TRACE<script>")
    assert "TRACE&lt;script&gt;" in page


def test_index_and_phpinfo_decoy_content():
    landing = index_page(DECOY, 8080)
    assert "Intranet File Portal" in landing
    assert 'action="/upload.php"' in landing
    assert "Port 8080" in landing

    info = phpinfo_page(DECOY)
    assert "session.upload_progress.enabled" in info
    assert DECOY.memory_limit in info or DECOY.php_version in info


def test_upload_success_page_escapes_filename():
    page = upload_success_page('shell"><img src=x>.php')
    assert "shell&quot;&gt;" in page
    assert "uploaded to" in page
    assert upload_success_page("") == upload_success_page("unnamed") or "unnamed" in upload_success_page("")
