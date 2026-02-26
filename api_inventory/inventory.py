from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .utils import (
    canonicalize_path,
    infer_body_format,
    normalize_url_forms,
    path_params_from_template,
    redact_headers,
    redact_url,
)


@dataclass
class Observation:
    method: str
    absolute_url: str
    path: str
    host: str
    query_params: dict[str, str | None] = field(default_factory=dict)
    path_params: list[str] = field(default_factory=list)
    request_headers: dict[str, str] = field(default_factory=dict)
    request_content_type: str = ""
    request_body: Any = None
    request_body_schema: dict[str, Any] | None = None
    response_status: int | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    response_content_type: str = ""
    response_body: Any = None
    response_body_schema: dict[str, Any] | None = None
    errors: list[dict[str, Any]] = field(default_factory=list)
    source: str = ""
    evidence: str = ""
    timestamp: str = ""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_method(method: str) -> str:
    method = (method or "UNKNOWN").upper().strip()
    return method if method else "UNKNOWN"


def endpoint_id(method: str, path: str, host: str) -> str:
    canon = f"{normalize_method(method)}|{canonicalize_path(path)}|{host.lower()}"
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16]


def observation_from_url(
    url: str,
    method: str,
    source: str,
    evidence: str,
    base_url: str | None = None,
) -> Observation:
    forms = normalize_url_forms(url=url, base_url=base_url)
    return Observation(
        method=normalize_method(method),
        absolute_url=forms.absolute,
        path=forms.path,
        host=forms.host,
        query_params=forms.query_params,
        path_params=path_params_from_template(forms.path),
        source=source,
        evidence=evidence,
        timestamp=now_iso(),
    )


def _merge_query_params(
    existing: list[dict[str, Any]],
    incoming: dict[str, str | None],
) -> list[dict[str, Any]]:
    names = {item["name"]: item for item in existing}
    for key, example in incoming.items():
        if key not in names:
            names[key] = {"name": key, "example": example}
        elif names[key].get("example") in (None, "") and example not in (None, ""):
            names[key]["example"] = example
    return sorted(names.values(), key=lambda x: x["name"])


def _unique_error_cases(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen = set()
    for item in items:
        key = json.dumps(item, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _cap_example_body(example: Any, max_body_bytes: int) -> Any:
    if example is None:
        return None
    if isinstance(example, (dict, list)):
        raw = json.dumps(example, ensure_ascii=True)
        encoded = raw.encode("utf-8", errors="ignore")
        if len(encoded) <= max_body_bytes:
            return example
        return encoded[:max_body_bytes].decode("utf-8", errors="ignore") + "\n...[truncated]"
    if isinstance(example, str):
        encoded = example.encode("utf-8", errors="ignore")
        if len(encoded) <= max_body_bytes:
            return example
        return encoded[:max_body_bytes].decode("utf-8", errors="ignore") + "\n...[truncated]"
    return example


def _runtime_error_case(obs: Observation) -> list[dict[str, Any]]:
    if obs.response_status is None:
        return []
    if int(obs.response_status) < 400:
        return []
    return [
        {
            "status": str(obs.response_status),
            "description": "Observed at runtime",
            "content_type": obs.response_content_type or "",
            "schema": obs.response_body_schema,
        }
    ]


def _init_record(obs: Observation, redact: bool, max_body_bytes: int) -> dict[str, Any]:
    eid = endpoint_id(obs.method, obs.path, obs.host)

    req_format, req_schema, req_example = infer_body_format(obs.request_content_type, obs.request_body)
    if obs.request_body_schema:
        req_schema = obs.request_body_schema

    resp_format, resp_schema, resp_example = infer_body_format(obs.response_content_type, obs.response_body)
    if obs.response_body_schema:
        resp_schema = obs.response_body_schema

    ts = obs.timestamp or now_iso()
    return {
        "id": eid,
        "method": normalize_method(obs.method),
        "url": {
            "absolute": redact_url(obs.absolute_url, enabled=redact),
            "path": canonicalize_path(obs.path),
        },
        "host": obs.host,
        "query_params": _merge_query_params([], obs.query_params),
        "path_params": sorted(set(obs.path_params)),
        "request": {
            "headers_sent": redact_headers(obs.request_headers, enabled=redact),
            "content_type": obs.request_content_type,
            "body_format": req_format,
            "body_schema": req_schema,
            "example_body": _cap_example_body(req_example, max_body_bytes=max_body_bytes),
        },
        "response": {
            "status": obs.response_status,
            "headers_received": redact_headers(obs.response_headers, enabled=redact),
            "content_type": obs.response_content_type,
            "body_format": resp_format,
            "body_schema": resp_schema,
            "example_body": _cap_example_body(resp_example, max_body_bytes=max_body_bytes),
        },
        "errors": _unique_error_cases(list(obs.errors) + _runtime_error_case(obs)),
        "sources": sorted({obs.source} - {""}),
        "evidence": [obs.evidence] if obs.evidence else [],
        "timestamps": {"first_seen": ts, "last_seen": ts},
        "_max_body_bytes": max_body_bytes,
    }


def _merge_record(record: dict[str, Any], obs: Observation, redact: bool) -> None:
    record["timestamps"]["last_seen"] = obs.timestamp or now_iso()
    record["query_params"] = _merge_query_params(record["query_params"], obs.query_params)
    record["path_params"] = sorted(set(record["path_params"]) | set(obs.path_params))

    if obs.source:
        record["sources"] = sorted(set(record["sources"]) | {obs.source})
    if obs.evidence:
        existing_evidence = set(record["evidence"])
        if obs.evidence not in existing_evidence:
            record["evidence"].append(obs.evidence)

    merged_req_headers = dict(record["request"]["headers_sent"])
    merged_req_headers.update(redact_headers(obs.request_headers, enabled=redact))
    record["request"]["headers_sent"] = merged_req_headers

    merged_resp_headers = dict(record["response"]["headers_received"])
    merged_resp_headers.update(redact_headers(obs.response_headers, enabled=redact))
    record["response"]["headers_received"] = merged_resp_headers

    if obs.request_content_type:
        record["request"]["content_type"] = obs.request_content_type
    if obs.response_content_type:
        record["response"]["content_type"] = obs.response_content_type
    if obs.response_status is not None:
        record["response"]["status"] = obs.response_status

    req_format, req_schema, req_example = infer_body_format(obs.request_content_type, obs.request_body)
    if obs.request_body_schema:
        req_schema = obs.request_body_schema
    if req_format != "unknown" or record["request"]["body_format"] == "unknown":
        record["request"]["body_format"] = req_format
    if req_schema and not record["request"].get("body_schema"):
        record["request"]["body_schema"] = req_schema
    if req_example is not None and record["request"].get("example_body") is None:
        record["request"]["example_body"] = _cap_example_body(
            req_example,
            max_body_bytes=record.get("_max_body_bytes", 200_000),
        )

    resp_format, resp_schema, resp_example = infer_body_format(obs.response_content_type, obs.response_body)
    if obs.response_body_schema:
        resp_schema = obs.response_body_schema
    if resp_format != "unknown" or record["response"]["body_format"] == "unknown":
        record["response"]["body_format"] = resp_format
    if resp_schema and not record["response"].get("body_schema"):
        record["response"]["body_schema"] = resp_schema
    if resp_example is not None and record["response"].get("example_body") is None:
        record["response"]["example_body"] = _cap_example_body(
            resp_example,
            max_body_bytes=record.get("_max_body_bytes", 200_000),
        )

    merged_errors = list(record.get("errors", [])) + list(obs.errors) + _runtime_error_case(obs)
    record["errors"] = _unique_error_cases(merged_errors)


def consolidate_observations(
    observations: list[Observation],
    redact: bool = True,
    max_body_bytes: int = 200_000,
) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for obs in observations:
        if not obs.host:
            forms = normalize_url_forms(obs.absolute_url)
            obs.host = forms.host
            obs.path = forms.path
            obs.query_params = forms.query_params
        obs.path = canonicalize_path(obs.path)
        obs.method = normalize_method(obs.method)
        if not obs.timestamp:
            obs.timestamp = now_iso()
        eid = endpoint_id(obs.method, obs.path, obs.host)
        if eid not in by_id:
            by_id[eid] = _init_record(obs, redact=redact, max_body_bytes=max_body_bytes)
        else:
            _merge_record(by_id[eid], obs, redact=redact)

    records = sorted(by_id.values(), key=lambda r: (r["method"], r["url"]["path"], r["host"]))
    for record in records:
        record.pop("_max_body_bytes", None)
    return records


def build_inventory_document(
    target_url: str,
    endpoints: list[dict[str, Any]],
    metadata: dict[str, Any],
    started_at: str,
    completed_at: str,
) -> dict[str, Any]:
    return {
        "version": 1,
        "target_url": target_url,
        "generated_at": completed_at,
        "started_at": started_at,
        "metadata": metadata,
        "summary": {
            "endpoint_count": len(endpoints),
            "methods": sorted({e["method"] for e in endpoints}),
            "sources": sorted({src for e in endpoints for src in e.get("sources", [])}),
        },
        "endpoints": endpoints,
    }
