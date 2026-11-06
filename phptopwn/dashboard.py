"""Fleet dashboard pages: per-region composition, node rollups, recent events.

All markup is static HTML with inline styles; there are no external assets,
scripts, fonts or trackers, so the collector never makes data leave the
machine to render a page. Pages are read-only views over the raw store.
"""
from __future__ import annotations

import html
from typing import Any

_FORMULA_NOTE = "counts are derived directly from the raw day files."


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{html.escape(title)}</title>"
        "<style>"
        "body{font-family:system-ui,sans-serif;margin:2rem;color:#1a1a2e;background:#f5f5f0}"
        "h1{font-size:1.4rem}h2{font-size:1.1rem;margin-top:1.6rem}"
        "table{border-collapse:collapse;background:#fff;width:100%;max-width:56rem}"
        "th,td{border:1px solid #d9d9d0;padding:.35rem .6rem;font-size:.9rem;text-align:left}"
        "th{background:#ececec}td.n{font-variant-numeric:tabular-nums}"
        ".bar{background:#b8563c;height:14px;min-width:2px}"
        ".muted{color:#666;font-size:.85rem}"
        "</style></head><body>"
        f"<h1>{html.escape(title)}</h1>{body}"
        "<p class='muted'>phptopwn collector — read-only view; "
        + _FORMULA_NOTE
        + "</p></body></html>"
    )


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(
        f"<th class='{'n' if index else ''}'>{html.escape(name)}</th>"
        for index, name in enumerate(headers)
    )
    body_rows = [
        "<tr>"
        + "".join(
            f"<td class='{'n' if index else ''}'>{html.escape(cell)}</td>"
            for index, cell in enumerate(row)
        )
        + "</tr>"
        for row in rows
    ]
    if not body_rows:
        body_rows = ["<tr><td colspan='" + str(len(headers)) + "'>no data</td></tr>"]
    return "<table><tr>" + head + "</tr>" + "".join(body_rows) + "</table>"


def _bar(value: float, max_value: float) -> str:
    if max_value <= 0:
        return "<div class='bar' style='width:2px'></div>"
    width = max(2, int(round(260 * value / max_value)))
    return f"<div class='bar' style='width:{width}px'></div>"


def _overview_days(store: Any, days: int = 14) -> list[dict[str, Any]]:
    available = store.available_days()[-days:]
    return [store.summary(day) for day in available]


def render_overview(store: Any) -> str:
    summaries = _overview_days(store)
    day_rows: list[list[str]] = []
    region_totals: dict[str, dict[str, int]] = {}
    for summary in summaries:
        totals = summary["totals"]
        day_rows.append(
            [
                summary["day"],
                str(totals["events"]),
                str(totals["exploits"]),
                str(summary["unique_ips"]),
                str(summary["unique_paths"]),
                str(len(summary["nodes"])),
            ]
        )
        for region, bucket in summary["regions"].items():
            target = region_totals.setdefault(region, {"events": 0, "exploits": 0})
            target["events"] += bucket["events"]
            target["exploits"] += bucket["exploits"]

    max_events = max((bucket["events"] for bucket in region_totals.values()), default=0)
    region_rows = [
        [
            region,
            str(bucket["events"]),
            str(bucket["exploits"]),
            _bar(bucket["events"], max_events),
        ]
        for region, bucket in sorted(
            region_totals.items(), key=lambda item: -item[1]["events"]
        )
    ]
    day_table = _table(
        ["day", "events", "exploits", "unique IPs", "unique paths", "nodes"], day_rows
    )
    region_table = _table(["region", "events (14d)", "exploits (14d)", ""], region_rows)
    links = (
        "<p><a href='/regions'>per-region composition</a>"
        " · <a href='/events'>recent events</a></p>"
    )
    return _page("phptopwn fleet overview", links + "<h2>Recent days</h2>" + day_table
                 + "<h2>Region composition (last 14 days)</h2>" + region_table)


def render_regions(store: Any) -> str:
    summaries = _overview_days(store)
    merged: dict[str, dict[str, Any]] = {}
    node_by_region: dict[str, dict[str, int]] = {}
    for summary in summaries:
        day = summary["day"]
        for region, bucket in summary["regions"].items():
            target = merged.setdefault(
                region, {"events": 0, "exploits": 0, "days": set(), "ips": set()}
            )
            target["events"] += bucket["events"]
            target["exploits"] += bucket["exploits"]
            target["days"].add(day)
        for node, node_bucket in summary["nodes"].items():
            region = _region_of_node(store, node)
            per_day = node_by_region.setdefault(region, {"events": 0})
            per_day["events"] += node_bucket["events"]
    rows = [
        [
            region,
            str(bucket["events"]),
            str(bucket["exploits"]),
            str(len(bucket["days"])),
            _bar(bucket["events"], max((b["events"] for b in merged.values()), default=0)),
        ]
        for region, bucket in sorted(merged.items(), key=lambda item: -item[1]["events"])
    ]
    table = _table(["region", "events", "exploits", "days observed", ""], rows)
    return _page("per-region composition", "<p><a href='/'>overview</a></p>" + table)


def _region_of_node(store: Any, node: str) -> str:
    return store.node_map.get(node, "unknown")


def render_events(records: list[dict[str, Any]]) -> str:
    rows: list[list[str]] = []
    for record in records:
        analysis = record.get("analysis") or {}
        metarec = record.get("collector") or {}
        request = record.get("request") or {}
        response = record.get("response") or {}
        rows.append(
            [
                str(record.get("timestamp") or ""),
                str(metarec.get("node", "unknown")),
                str(record.get("client", {}).get("ip", "")),
                str(request.get("method", "")),
                str(request.get("path", ""))[:120],
                str(response.get("status", "")),
                "exploit" if analysis.get("is_exploit") else "benign",
            ]
        )
    table = _table(
        ["timestamp", "node", "source IP", "method", "path", "status", "verdict"], rows
    )
    back = "<p><a href='/'>overview</a> · <a href='/regions'>regions</a></p>"
    return _page("recent events", back + table)
