"""Tests for the pure parsers in phptopwn.parsing."""
from __future__ import annotations

import hashlib

from conftest import BOUNDARY, build_capture, multipart_body

from phptopwn.parsing import (
    enrich_capture,
    extract_filename,
    find_webshell_markers,
    parse_content_type,
    parse_multipart,
    parse_part_headers,
    parse_query,
    parse_urlencoded,
)


def test_parse_content_type_variants():
    assert parse_content_type("") == ("", {})
    assert parse_content_type("application/x-php; charset=utf-8")[0] == "application/x-php"
    mime, params = parse_content_type('multipart/form-data; boundary="abc-123"; charset=utf-8')
    assert mime == "multipart/form-data"
    assert params == {"boundary": "abc-123", "charset": "utf-8"}
    _, params = parse_content_type("text/plain; a='single'; b=bare")
    assert params["a"] == "single" and params["b"] == "bare"


def test_extract_filename_lifecycle():
    assert extract_filename("") is None
    assert extract_filename('form-data; name="f"') is None
    plain = 'form-data; name="f"; filename="x.php"'
    assert extract_filename(plain) == "x.php"
    quoted = 'form-data; name="f"; filename="a\\"b.c"'
    assert extract_filename(quoted) == 'a"b.c'
    rfc = "form-data; name=\"f\"; filename*=utf-8''step%20one%2Fthree.php"
    assert extract_filename(rfc) == "step one/three.php"
    single = 'form-data; name=f; filename=\'y\''
    assert extract_filename(single) == "y"


def test_parse_part_headers_simple_and_folded():
    headers, size, folded = parse_part_headers(b'Content-Disposition: form-data; name="a"\r\nX: y')
    assert headers["content-disposition"] == 'form-data; name="a"'
    assert folded is False
    assert size == len(b'Content-Disposition: form-data; name="a"\r\nX: y')

    headers, _, folded = parse_part_headers(b"A: b\r\n   continuation\r\nC: d")
    assert folded is True
    assert headers["a"] == "b continuation"

    headers, _, folded = parse_part_headers(b"garbage line\r\nA: b")
    assert folded is True
    assert headers == {"a": "b"}


def test_parse_multipart_basic_field_and_file():
    body, boundary = multipart_body(
        [
            {"name": "note", "data": "hello"},
            {
                "name": "file",
                "filename": "shell.php",
                "content_type": "application/x-php",
                "data": b"<?php eval($_POST[1]);?>",
            },
        ]
    )
    result = parse_multipart(body, boundary)
    assert result.boundary_found and result.closed and not result.malformed
    assert result.boundary_occurrences == 3
    assert len(result.parts) == 2
    note, shell = result.parts
    assert (note.name, note.filename, note.data, note.size) == ("note", None, b"hello", 5)
    assert shell.filename == "shell.php"
    assert shell.sha256 == hashlib.sha256(b"<?php eval($_POST[1]);?>").hexdigest()
    assert result.file_parts == [shell]
    assert not result.duplicate_filenames


def test_parse_multipart_missing_and_mangled_boundary():
    body, _ = multipart_body([{"name": "note", "data": "hi"}])
    missing = parse_multipart(body, "totally-unrelated-boundary")
    assert missing.boundary_found is False
    assert missing.parts == []

    empty = parse_multipart(body, "")
    assert empty.malformed is True
    assert empty.parts == []


def test_parse_multipart_flags():
    body, boundary = multipart_body(
        [
            {"name": "one", "data": "one", "filename": "a.txt"},
            {"name": "two", "data": "two", "filename": "a.txt"},
            {"name": "three", "data": "bigname", "filename": "B" * 400 + ".txt"},
            {"name": "four", "data": "deep", "filename": "../../etc/passwd"},
        ]
    )
    result = parse_multipart(body, boundary)
    assert result.duplicate_filenames == ["a.txt"]
    assert result.long_filenames and result.long_filenames[0].startswith("B")
    assert result.filename_traversal == ["../../etc/passwd"]


def test_parse_multipart_part_header_and_fold_flags():
    payload = (
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="f"\r\n'
        "X-Extra: " + "A" * 300 + "\r\n"
        "\r\n"
        "value\r\n"
        f"--{BOUNDARY}\r\n"
        'Content-Disposition: form-data; name="g"\r\n'
        "X-Fold: line1\r\n"
        "   line2\r\n"
        "\r\n"
        "two\r\n"
        f"--{BOUNDARY}--\r\n"
    ).encode("latin-1")
    result = parse_multipart(payload, BOUNDARY)
    assert result.max_header_size >= 300
    assert result.folded_headers is True


def test_parse_multipart_nested_boundary():
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
    result = parse_multipart(body, boundary)
    assert result.nested_boundary is True


def test_part_limit_flood_is_bounded():
    body, boundary = multipart_body([{"name": f"p{i}", "data": "x"} for i in range(600)])
    result = parse_multipart(body, boundary, max_parts=20)
    assert result.part_limit_reached is True
    assert len(result.parts) == 20


def test_malformed_part_after_boundary():
    body = b"--bnd\r\nNOT-CLRF-SEPARATED\r\n--bnd--\r\n"
    result = parse_multipart(body, "bnd")
    assert result.boundary_found is True
    assert result.parts == [] and result.malformed is True


def test_part_without_separator_is_malformed():
    body = b"--bnd\nContent-Disposition: form-data; name=\"x\"\n--bnd--\n"
    result = parse_multipart(body, "bnd")
    assert result.malformed is True


def test_truncated_probe_marks_last_part():
    body, boundary = multipart_body([{"name": "a", "data": "x"}, {"name": "b", "data": "y"}])
    # Simulate the byte probe being cut before the closing delimiter arrives.
    probe = body[: -len(f"--{boundary}--\r\n".encode())]
    result = parse_multipart(probe, boundary, truncated=len(probe) < len(body))
    assert result.closed is False
    assert result.parts[-1].truncated is True
    assert result.parts[0].truncated is False
    assert result.parts[-1].data.startswith(b"y")


def test_find_webshell_markers():
    markers = find_webshell_markers(b"<?php system($_GET['c']); ?>")
    assert "<?php" in markers and "system(" in markers
    assert find_webshell_markers(b"nothing here") == []


def test_urlencoded_and_query_parsers():
    assert parse_urlencoded(b"a=1&b=smth+else") == {"a": "1", "b": "smth else"}
    assert parse_query("") == {}
    assert parse_query("x=%2Fetc%2Fpasswd") == {"x": "/etc/passwd"}


def test_enrich_capture_multipart_and_form():
    body, boundary = multipart_body(
        [
            {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": "race"},
            {"name": "file", "filename": "shell.php", "content_type": "application/x-php", "data": b"<?php {"},
        ]
    )
    capture = build_capture(body=body, headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
    enrich_capture(capture)
    assert capture.multipart is not None
    assert len(capture.multipart.parts) == 2
    assert capture.form["PHP_SESSION_UPLOAD_PROGRESS"] == "race"
    assert "file" not in capture.form  # file part must not become a form field

    form_capture = build_capture(
        body=b"a=1&b=2",
        query="a=3",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    enrich_capture(form_capture)
    assert form_capture.form == {"a": "1", "b": "2"}
    assert form_capture.query_params == {"a": "3"}
