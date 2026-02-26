from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

from .inventory import Observation
from .utils import normalize_url_forms, path_params_from_template

LOGGER = logging.getLogger(__name__)

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None

try:
    from . import find_swagger_url  # type: ignore
except Exception as exc:  # pragma: no cover
    find_swagger_url = None  # type: ignore
    IMPORT_ERROR = exc
else:
    IMPORT_ERROR = None


@dataclass
class SwaggerIngestResult:
    observations: list[Observation]
    metadata: dict[str, Any]
    warnings: list[str]


def build_swagger_candidates(
    discovered_paths: list[str] | None = None,
    only_openapi: bool = False,
    only_ui: bool = False,
) -> list[str]:
    if not find_swagger_url:
        return []
    return find_swagger_url.build_candidate_paths(
        discovered_paths=discovered_paths,
        only_openapi=only_openapi,
        only_ui=only_ui,
    )


def _resolve_ref(doc: dict[str, Any], value: Any, max_depth: int = 8) -> Any:
    if max_depth <= 0:
        return value
    if isinstance(value, dict) and "$ref" in value and isinstance(value["$ref"], str):
        ref = value["$ref"]
        if not ref.startswith("#/"):
            return value
        current: Any = doc
        for part in ref[2:].split("/"):
            if not isinstance(current, dict):
                return value
            current = current.get(part)
            if current is None:
                return value
        return _resolve_ref(doc, current, max_depth=max_depth - 1)

    if isinstance(value, dict):
        return {k: _resolve_ref(doc, v, max_depth=max_depth - 1) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_ref(doc, v, max_depth=max_depth - 1) for v in value]
    return value


def _extract_example(content_item: dict[str, Any]) -> Any:
    if not isinstance(content_item, dict):
        return None
    if "example" in content_item:
        return content_item.get("example")
    examples = content_item.get("examples")
    if isinstance(examples, dict):
        for example_item in examples.values():
            if isinstance(example_item, dict) and "value" in example_item:
                return example_item["value"]
    return None


def _parse_parameters(params: list[Any], spec_doc: dict[str, Any]) -> tuple[dict[str, str | None], list[str], dict[str, str]]:
    query_params: dict[str, str | None] = {}
    path_params: list[str] = []
    header_params: dict[str, str] = {}

    for param in params:
        resolved = _resolve_ref(spec_doc, param)
        if not isinstance(resolved, dict):
            continue
        name = resolved.get("name")
        where = resolved.get("in")
        if not name or not where:
            continue

        schema = resolved.get("schema") if isinstance(resolved.get("schema"), dict) else {}
        example = resolved.get("example")
        if example is None and isinstance(schema, dict):
            example = schema.get("example")

        if where == "query":
            query_params[str(name)] = None if example is None else str(example)
        elif where == "path":
            path_params.append(str(name))
        elif where == "header":
            header_params[str(name)] = None if example is None else str(example)

    return query_params, sorted(set(path_params)), header_params


def _choose_content(contents: Any) -> tuple[str, dict[str, Any] | None]:
    if not isinstance(contents, dict) or not contents:
        return "", None
    if "application/json" in contents:
        return "application/json", contents["application/json"]
    first = next(iter(contents.items()))
    if isinstance(first, tuple) and len(first) == 2:
        key, value = first
        if isinstance(key, str) and isinstance(value, dict):
            return key, value
    return "", None


def _status_code_to_int(status: str) -> int | None:
    if status.isdigit():
        return int(status)
    return None


def parse_openapi_document(
    spec_doc: dict[str, Any],
    spec_url: str,
    base_url: str,
) -> list[Observation]:
    observations: list[Observation] = []
    paths = spec_doc.get("paths") if isinstance(spec_doc, dict) else None
    if not isinstance(paths, dict):
        return observations

    host_forms = normalize_url_forms(base_url)
    for raw_path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        template_params = path_params_from_template(str(raw_path))
        path_level_params = path_item.get("parameters") if isinstance(path_item.get("parameters"), list) else []

        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            op_params = operation.get("parameters") if isinstance(operation.get("parameters"), list) else []
            all_params = list(path_level_params) + list(op_params)
            query_params, explicit_path_params, header_params = _parse_parameters(all_params, spec_doc)
            all_path_params = sorted(set(template_params) | set(explicit_path_params))

            request_content_type = ""
            request_schema = None
            request_example = None

            request_body = _resolve_ref(spec_doc, operation.get("requestBody"))
            if isinstance(request_body, dict):
                r_content_type, r_content_item = _choose_content(request_body.get("content"))
                request_content_type = r_content_type
                if isinstance(r_content_item, dict):
                    request_schema = _resolve_ref(spec_doc, r_content_item.get("schema"))
                    request_example = _extract_example(r_content_item)

            responses = operation.get("responses") if isinstance(operation.get("responses"), dict) else {}
            response_status: int | None = None
            response_content_type = ""
            response_schema = None
            response_example = None
            error_cases: list[dict[str, Any]] = []

            for status_code, response_item in responses.items():
                resolved_resp = _resolve_ref(spec_doc, response_item)
                if not isinstance(resolved_resp, dict):
                    continue
                desc = resolved_resp.get("description")
                r_ct, r_content_item = _choose_content(resolved_resp.get("content"))
                r_schema = _resolve_ref(spec_doc, r_content_item.get("schema") if isinstance(r_content_item, dict) else None)
                r_example = _extract_example(r_content_item or {})

                is_error = str(status_code).startswith(("4", "5")) or str(status_code).lower() == "default"
                if is_error:
                    error_cases.append(
                        {
                            "status": str(status_code),
                            "description": desc,
                            "content_type": r_ct,
                            "schema": r_schema,
                        }
                    )

                numeric = _status_code_to_int(str(status_code))
                if response_status is None and numeric is not None and 200 <= numeric < 300:
                    response_status = numeric
                    response_content_type = r_ct
                    response_schema = r_schema
                    response_example = r_example

            if response_status is None and responses:
                first_status, first_item = next(iter(responses.items()))
                resolved_first = _resolve_ref(spec_doc, first_item)
                r_ct, r_content_item = _choose_content(
                    resolved_first.get("content") if isinstance(resolved_first, dict) else None
                )
                response_status = _status_code_to_int(str(first_status))
                response_content_type = r_ct
                response_schema = _resolve_ref(spec_doc, r_content_item.get("schema") if isinstance(r_content_item, dict) else None)
                response_example = _extract_example(r_content_item or {})

            absolute_url = urljoin(base_url if base_url.endswith("/") else f"{base_url}/", str(raw_path).lstrip("/"))
            forms = normalize_url_forms(absolute_url)
            observations.append(
                Observation(
                    method=method.upper(),
                    absolute_url=forms.absolute,
                    path=forms.path,
                    host=forms.host or host_forms.host,
                    query_params=query_params,
                    path_params=all_path_params,
                    request_headers={k: v for k, v in header_params.items() if v is not None},
                    request_content_type=request_content_type,
                    request_body=request_example,
                    request_body_schema=request_schema if isinstance(request_schema, dict) else None,
                    response_status=response_status,
                    response_headers={},
                    response_content_type=response_content_type,
                    response_body=response_example,
                    response_body_schema=response_schema if isinstance(response_schema, dict) else None,
                    errors=error_cases,
                    source="swagger",
                    evidence=f"{spec_url}#{method.upper()} {forms.path}",
                )
            )

    return observations


async def _fetch_url_text(url: str, timeout: float, headers: dict[str, str]) -> tuple[str | None, str]:
    if aiohttp is None:
        return None, "aiohttp is not installed; cannot fetch swagger spec URLs"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers=headers,
                allow_redirects=True,
                ssl=False,
            ) as response:
                if response.status >= 400:
                    return None, f"failed to fetch swagger spec ({response.status}) at {url}"
                body = await response.text(errors="ignore")
                return body, ""
    except Exception as exc:
        return None, f"failed to fetch swagger spec at {url}: {exc}"


def _parse_spec_text(raw: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    if yaml is not None:
        try:
            parsed_yaml = yaml.safe_load(raw)
            if isinstance(parsed_yaml, dict):
                return parsed_yaml
        except Exception:
            return None
    return None


def collect_from_swagger(
    base_url: str,
    timeout: float,
    concurrency: int,
    user_agent: str,
    headers: dict[str, str] | None = None,
    discovered_paths: list[str] | None = None,
) -> SwaggerIngestResult:
    warnings: list[str] = []
    metadata: dict[str, Any] = {
        "swagger_hits": [],
        "swagger_source_urls": [],
        "swagger_candidate_count": 0,
    }

    if IMPORT_ERROR or not find_swagger_url:
        warnings.append(f"find_swagger_url import failed: {IMPORT_ERROR}")
        return SwaggerIngestResult(observations=[], metadata=metadata, warnings=warnings)

    merged_headers = {"User-Agent": user_agent}
    if headers:
        merged_headers.update(headers)

    try:
        hits = find_swagger_url.probe_swagger_hits(
            base_url=base_url,
            discovered_paths=discovered_paths,
            timeout=timeout,
            concurrency=concurrency,
            allow_redirects=True,
            max_bytes=250_000,
            only_openapi=False,
            only_ui=False,
        )
    except Exception as exc:
        warnings.append(f"swagger probing failed: {exc}")
        hits = []

    metadata["swagger_hits"] = [
        {
            "path": h.path,
            "url": h.url,
            "status": h.status,
            "content_type": h.content_type,
            "score": h.score,
            "kind": h.kind,
        }
        for h in hits
    ]

    openapi_hits = [h for h in hits if h.kind in {"openapi-json", "openapi-yaml"}]
    metadata["swagger_candidate_count"] = len(
        build_swagger_candidates(discovered_paths=discovered_paths, only_openapi=False, only_ui=False)
    )

    observations: list[Observation] = []
    for hit in openapi_hits:
        metadata["swagger_source_urls"].append(hit.url)
        raw, warning = asyncio.run(_fetch_url_text(hit.url, timeout=timeout, headers=merged_headers))
        if warning:
            warnings.append(warning)
            continue
        if raw is None:
            continue
        spec_doc = _parse_spec_text(raw)
        if not spec_doc:
            warnings.append(f"unable to parse swagger spec at {hit.url}")
            continue
        observations.extend(parse_openapi_document(spec_doc=spec_doc, spec_url=hit.url, base_url=base_url))

    return SwaggerIngestResult(observations=observations, metadata=metadata, warnings=warnings)
