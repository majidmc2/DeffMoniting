from __future__ import annotations

import json
from typing import Any


def _endpoint_change_fingerprint(endpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "method": endpoint.get("method"),
        "path": endpoint.get("url", {}).get("path"),
        "host": endpoint.get("host"),
        "query_params": endpoint.get("query_params", []),
        "path_params": endpoint.get("path_params", []),
        "request": {
            "headers_sent": endpoint.get("request", {}).get("headers_sent"),
            "content_type": endpoint.get("request", {}).get("content_type"),
            "body_format": endpoint.get("request", {}).get("body_format"),
            "body_schema": endpoint.get("request", {}).get("body_schema"),
        },
        "response": {
            "status": endpoint.get("response", {}).get("status"),
            "headers_received": endpoint.get("response", {}).get("headers_received"),
            "content_type": endpoint.get("response", {}).get("content_type"),
            "body_format": endpoint.get("response", {}).get("body_format"),
            "body_schema": endpoint.get("response", {}).get("body_schema"),
        },
        "errors": endpoint.get("errors", []),
    }


def _to_map(endpoints: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for endpoint in endpoints:
        endpoint_id = endpoint.get("id")
        if endpoint_id:
            out[str(endpoint_id)] = endpoint
    return out


def diff_inventories(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    prev_map = _to_map(previous.get("endpoints", []))
    curr_map = _to_map(current.get("endpoints", []))

    prev_ids = set(prev_map)
    curr_ids = set(curr_map)

    added_ids = sorted(curr_ids - prev_ids)
    removed_ids = sorted(prev_ids - curr_ids)
    shared_ids = sorted(prev_ids & curr_ids)

    changed: list[dict[str, Any]] = []
    for eid in shared_ids:
        prev_fp = _endpoint_change_fingerprint(prev_map[eid])
        curr_fp = _endpoint_change_fingerprint(curr_map[eid])
        if json.dumps(prev_fp, sort_keys=True) != json.dumps(curr_fp, sort_keys=True):
            changed.append(
                {
                    "id": eid,
                    "method": curr_map[eid].get("method"),
                    "path": curr_map[eid].get("url", {}).get("path"),
                    "host": curr_map[eid].get("host"),
                    "previous": prev_fp,
                    "current": curr_fp,
                }
            )

    diff_result = {
        "summary": {
            "previous_endpoint_count": len(previous.get("endpoints", [])),
            "current_endpoint_count": len(current.get("endpoints", [])),
            "added": len(added_ids),
            "removed": len(removed_ids),
            "changed": len(changed),
        },
        "added": [curr_map[eid] for eid in added_ids],
        "removed": [prev_map[eid] for eid in removed_ids],
        "changed": changed,
    }
    return diff_result


def render_diff_markdown(diff_result: dict[str, Any]) -> str:
    summary = diff_result.get("summary", {})
    lines = [
        "# API Inventory Diff",
        "",
        f"- Previous endpoints: {summary.get('previous_endpoint_count', 0)}",
        f"- Current endpoints: {summary.get('current_endpoint_count', 0)}",
        f"- Added: {summary.get('added', 0)}",
        f"- Removed: {summary.get('removed', 0)}",
        f"- Changed: {summary.get('changed', 0)}",
        "",
    ]

    if diff_result.get("added"):
        lines.append("## Added")
        for endpoint in diff_result["added"][:100]:
            lines.append(f"- `{endpoint.get('method')} {endpoint.get('url', {}).get('path')}`")
        lines.append("")

    if diff_result.get("removed"):
        lines.append("## Removed")
        for endpoint in diff_result["removed"][:100]:
            lines.append(f"- `{endpoint.get('method')} {endpoint.get('url', {}).get('path')}`")
        lines.append("")

    if diff_result.get("changed"):
        lines.append("## Changed")
        for changed in diff_result["changed"][:100]:
            lines.append(f"- `{changed.get('method')} {changed.get('path')}`")
        lines.append("")

    return "\n".join(lines).strip() + "\n"
