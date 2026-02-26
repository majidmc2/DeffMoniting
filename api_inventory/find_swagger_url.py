#!/usr/bin/env python3
"""Swagger/OpenAPI path probe module with importable entry function."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass
from typing import Iterable, Optional, Set
from urllib.parse import urljoin, urlparse

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None


DEFAULT_PATHS = [
    "/swagger",
    "/swagger-ui/",
    "/swagger-ui/index.html",
    "/swagger-ui.html",
    "/swagger/",
    "/swagger/index.html",
    "/swagger/ui/",
    "/swagger/ui/index",
    "/swagger/ui/index.html",
    "/swagger-ui",
    "/docs/",
    "/docs/index.html",
    "/api/docs/",
    "/api-docs/",
    "/v1/swagger/",
    "/v1/swagger-ui/",
    "/v2/swagger/",
    "/v2/swagger-ui/",
    "/v1/docs/",
    "/api/v1/docs/",
    "/api/v1/swagger/",
    "/api/v1/swagger-ui/",
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api-docs",
    "/api-docs.json",
    "/api-docs.yaml",
    "/api/docs",
    "/swagger/docs",
    "/swagger/docs/v1",
    "/swagger/docs/v2",
    "/v2/api-docs",
    "/v3/api-docs",
    "/v3/api-docs/",
    "/v3/api-docs.yaml",
    "/v3/api-docs.yml",
    "/v3/api-docs/swagger-config",
    "/swagger/v1/swagger.json",
    "/swagger/v1/swagger.yaml",
    "/swagger/v2/swagger.json",
    "/swagger/v2/swagger.yaml",
    "/swagger/{documentName}/swagger.json",
    "/swagger/{documentName}/swagger.yaml",
    "/swagger/{service}/swagger.json",
    "/openapi/{service}.json",
    "/openapi/{version}.json",
    "/spec",
    "/spec.json",
    "/spec.yaml",
    "/redoc",
    "/redoc/",
    "/redoc/index.html",
    "/api/redoc",
    "/docs/redoc",
    "/reference",
    "/api/reference",
    "/rapidoc",
    "/rapidoc/",
    "/rapidoc/index.html",
    "/api/rapidoc",
    "/scalar",
    "/api/scalar",
    "/stoplight",
    "/docs/reference",
    "/reference/docs",
    "/api-reference",
    "/api-reference/",
    "/schema/",
    "/schema.json",
    "/schema.yaml",
    "/openapi/",
    "/swaggerui/",
    "/swaggerui/index.html",
    "/apidocs/",
    "/swagger-json",
    "/swagger-resources",
    "/swagger-resources/configuration/ui",
    "/swagger-resources/configuration/security",
    "/swagger",
    "/swagger/swagger.json",
    "/swagger/ui",
    "/api/documentation",
    "/api/documentation/",
    "/api-docs/v1/swagger.json",
    "/api-docs/v1/swagger.yaml",
    "/swagger/doc.json",
    "/docs/swagger/index.html",
    "/apispec",
    "/apispec.json",
    "/api-json",
    "/api-json/",
    "/docs-json",
    "/docs-json/",
    "/api/swagger-ui.html",
    "/api/swagger-ui/index.html",
    "/docs/openapi.json",
    "/docs/openapi.yaml",
    "/docs/openapi.yml",
    "/openapi/v1.json",
    "/openapi/v2.json",
    "/openapi/v3.json",
    "/q/openapi",
    "/q/swagger-ui",
    "/q/swagger-ui/",
    "/q/swagger-ui/index.html",
    "/actuator/openapi",
    "/management/openapi",
    "/swagger/v1/openapi.json",
    "/swagger/v1/openapi.yaml",
    "/swagger/v1/openapi.yml",
    "/swagger/v2/openapi.json",
    "/api/schema/",
    "/api/schema",
    "/api/schema/swagger-ui/",
    "/api/schema/redoc/",
    "/swagger/?format=openapi",
    "/swagger.json?format=openapi",
    "/openapi?format=json",
    "/api/openapi",
    "/api/openapi.yml",
    "/api/openapi?format=json",
    "/_openapi",
    "/_swagger",
]

COMMON_PREFIXES = [
    "",
    "/api",
    "/api/",
    "/v1",
    "/v1/",
    "/v2",
    "/v2/",
    "/v3",
    "/v3/",
    "/internal",
    "/internal/",
    "/public",
    "/public/",
    "/platform",
    "/platform/",
    "/gateway",
    "/gateway/",
    "/service",
    "/service/",
]

PLACEHOLDER_EXPANSIONS = {
    "{documentName}": ["v1", "v2", "default", "public", "internal"],
    "{service}": ["api", "service", "public", "internal"],
    "{version}": ["v1", "v2", "v3"],
}

OPENAPI_JSON_HINTS = ['"openapi"', '"swagger"', '"paths"']
OPENAPI_YAML_HINTS = ["openapi:", "swagger:", "paths:"]
SWAGGER_UI_HINTS = ["swagger-ui", "Swagger UI"]
REDOC_HINTS = ["redoc", "ReDoc"]
RAPIDOC_HINTS = ["rapidoc"]
SCALAR_HINTS = ["@scalar/api-reference", "scalar", "api-reference"]
STOPLIGHT_HINTS = ["stoplight", "elements-api", "stoplight elements"]
SWAGGER_CONFIG_HINTS = ["swagger-config", "validatorUrl", "oauth2RedirectUrl"]
DOC_PATH_HINTS = ("swagger", "openapi", "api-docs", "apidocs", "redoc", "rapidoc", "scalar", "reference", "docs")
LOGIN_OR_ERROR_HINTS = (
    "not found",
    "404",
    "signin",
    "sign in",
    "log in",
    "login",
    "access denied",
    "forbidden",
    "unauthorized",
)


@dataclass
class Hit:
    path: str
    url: str
    status: int
    content_type: str
    score: int
    kind: str
    title: str


def normalize_path(path: str) -> str:
    if not path.startswith("/"):
        path = "/" + path
    return re.sub(r"/{2,}", "/", path)


def join_prefix(prefix: str, path: str) -> str:
    prefix = prefix.strip()
    path = normalize_path(path)
    if not prefix:
        return path
    if not prefix.startswith("/"):
        prefix = "/" + prefix
    prefix = re.sub(r"/{2,}", "/", prefix)
    if prefix.endswith("/"):
        return re.sub(r"/{2,}", "/", prefix[:-1] + path)
    return re.sub(r"/{2,}", "/", prefix + path)


def expand_placeholders(path: str) -> list[str]:
    expanded = [path]
    for placeholder, values in PLACEHOLDER_EXPANSIONS.items():
        next_list: list[str] = []
        for current in expanded:
            if placeholder in current:
                for v in values:
                    next_list.append(current.replace(placeholder, v))
            else:
                next_list.append(current)
        expanded = next_list
    return sorted({normalize_path(p) for p in expanded})


def generate_candidates(base_paths: Iterable[str], prefixes: Iterable[str]) -> list[str]:
    all_paths: Set[str] = set()
    for raw in base_paths:
        for concrete in expand_placeholders(raw):
            all_paths.add(normalize_path(concrete))
            for pref in prefixes:
                all_paths.add(normalize_path(join_prefix(pref, concrete)))
    cleaned = {
        re.sub(r"^/(api|v1|v2|v3)/\1(/|$)", r"/\1\2", path)
        for path in all_paths
    }
    return sorted(cleaned)


def filter_candidates(candidates: list[str], only_openapi: bool, only_ui: bool) -> list[str]:
    if not only_openapi and not only_ui:
        return candidates
    output: list[str] = []
    for p in candidates:
        lp = p.lower()
        is_spec = (
            any(lp.endswith(x) for x in (".json", ".yaml", ".yml"))
            or "api-docs" in lp
            or "api-json" in lp
            or "docs-json" in lp
            or "/schema" in lp
            or "spec" in lp
            or "openapi" in lp
            or "swagger.json" in lp
        )
        is_ui = any(
            k in lp
            for k in (
                "swagger-ui",
                "swagger-ui.html",
                "/docs",
                "redoc",
                "rapidoc",
                "scalar",
                "stoplight",
                "api-reference",
                "reference",
            )
        )
        if only_openapi and is_spec:
            output.append(p)
        elif only_ui and is_ui:
            output.append(p)
    return sorted(set(output))


def _is_hint_path(path: str) -> bool:
    lp = path.lower()
    return any(k in lp for k in DOC_PATH_HINTS)


def build_candidate_paths(
    discovered_paths: Iterable[str] | None = None,
    only_openapi: bool = False,
    only_ui: bool = False,
) -> list[str]:
    base_paths = set(DEFAULT_PATHS)
    for raw in discovered_paths or []:
        parsed = urlparse(raw)
        path = parsed.path if parsed.scheme and parsed.netloc else raw
        if not path:
            continue
        normalized = normalize_path(path)
        if _is_hint_path(normalized):
            base_paths.add(normalized)
    candidates = generate_candidates(sorted(base_paths), COMMON_PREFIXES)
    return filter_candidates(candidates, only_openapi=only_openapi, only_ui=only_ui)


def _looks_like_openapi_json(text: str) -> bool:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return False
    if not isinstance(parsed, dict):
        return False

    has_version = isinstance(parsed.get("openapi"), str) or isinstance(parsed.get("swagger"), str)
    has_paths = isinstance(parsed.get("paths"), dict)
    has_info = isinstance(parsed.get("info"), dict)
    has_structure = any(k in parsed for k in ("components", "definitions", "servers", "host", "basePath"))
    return bool((has_version and has_paths) or (has_paths and has_info and has_structure))


def _looks_like_swagger_config_json(text: str) -> bool:
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return False
    if not isinstance(parsed, dict):
        return False

    if isinstance(parsed.get("url"), str):
        return True
    urls = parsed.get("urls")
    if isinstance(urls, list) and urls:
        return True
    return any(k in parsed for k in ("validatorUrl", "oauth2RedirectUrl"))


def _looks_like_openapi_yaml(text: str) -> bool:
    first = text[:5000]
    lower = first.lower()
    if "<html" in lower or "<!doctype html" in lower:
        return False
    has_version = re.search(r"(?mi)^\s*(openapi|swagger)\s*:\s*['\"]?[0-9v.]+", first) is not None
    has_paths = re.search(r"(?mi)^\s*paths\s*:\s*$", first) is not None
    return has_version and has_paths


def _looks_like_swagger_ui(text: str) -> bool:
    lower = text.lower()
    return any(
        marker in lower
        for marker in (
            "swaggeruibundle(",
            "swagger-ui-bundle.js",
            "swagger-ui-standalone-preset",
            "id=\"swagger-ui\"",
            "id='swagger-ui'",
        )
    )


def _looks_like_redoc(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in ("<redoc", "redoc.standalone.js", "redoc-init"))


def _looks_like_rapidoc(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in ("<rapi-doc", "rapidoc-min", "rapidoc "))


def _looks_like_scalar(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in ("@scalar/api-reference", "scalar api reference", "<scalar-api-reference"))


def _looks_like_stoplight(text: str) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in ("stoplight elements", "<elements-api", "stoplightio"))


def _looks_like_login_or_error_page(text: str) -> bool:
    lower = text.lower()
    return any(hint in lower for hint in LOGIN_OR_ERROR_HINTS)


def score_response(path: str, status: int, content_type: str, body: str) -> tuple[int, str, str]:
    ct = (content_type or "").lower()
    text = (body or "")[:200_000]
    lower = text.lower()
    p = (path or "").lower()

    # Response code is not sufficient; treat only plausible statuses as candidates.
    if status >= 500 or status == 404:
        return -10, "unknown", ""

    score = 0
    kind = "unknown"
    title = ""

    if 200 <= status < 300:
        score += 1
    elif status in (401, 403):
        score += 0
    else:
        return -6, "unknown", ""

    if any(h in p for h in DOC_PATH_HINTS):
        score += 1

    if _looks_like_openapi_json(text):
        score += 8
        kind = "openapi-json"
        title = "OpenAPI/Swagger spec (JSON)"
    elif _looks_like_openapi_yaml(text):
        score += 8
        kind = "openapi-yaml"
        title = "OpenAPI/Swagger spec (YAML)"
    elif _looks_like_swagger_config_json(text):
        score += 6
        kind = "swagger-config"
        title = "Swagger UI config"
    elif _looks_like_swagger_ui(text):
        score += 6
        kind = "swagger-ui"
        title = "Swagger UI"
    elif _looks_like_redoc(text):
        score += 6
        kind = "redoc"
        title = "ReDoc UI"
    elif _looks_like_rapidoc(text):
        score += 6
        kind = "rapidoc"
        title = "RapiDoc UI"
    elif _looks_like_scalar(text):
        score += 6
        kind = "scalar"
        title = "Scalar API Reference"
    elif _looks_like_stoplight(text):
        score += 6
        kind = "stoplight"
        title = "Stoplight Elements"
    else:
        # Avoid false positives such as generic 200 login/error pages.
        if _looks_like_login_or_error_page(lower):
            score -= 5

    if kind in {"openapi-json", "swagger-config"} and "json" not in ct and "javascript" not in ct:
        score -= 1
    if kind == "openapi-yaml" and not any(x in ct for x in ("yaml", "text/plain", "octet-stream")):
        score -= 1

    if any(h in lower for h in OPENAPI_JSON_HINTS):
        score += 1
    if any(h in lower for h in OPENAPI_YAML_HINTS):
        score += 1
    if any(
        h.lower() in lower
        for h in SWAGGER_UI_HINTS + REDOC_HINTS + RAPIDOC_HINTS + SCALAR_HINTS + STOPLIGHT_HINTS + SWAGGER_CONFIG_HINTS
    ):
        score += 1

    return score, kind, title


def validate_base_url(base_url: str) -> str:
    if not re.match(r"^https?://", base_url, re.IGNORECASE):
        base_url = "https://" + base_url
    parsed = urlparse(base_url)
    if not parsed.netloc:
        raise ValueError(f"Invalid base URL: {base_url}")
    if not base_url.endswith("/"):
        base_url += "/"
    return base_url


async def _fetch_candidate(
    session: "aiohttp.ClientSession",
    base_url: str,
    path: str,
    timeout: float,
    allow_redirects: bool,
    max_bytes: int,
) -> Optional[Hit]:
    url = urljoin(base_url, path.lstrip("/"))
    try:
        async with session.get(
            url,
            allow_redirects=allow_redirects,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": "swagger-path-probe/1.0"},
        ) as resp:
            body = (await resp.content.read(max_bytes)).decode(errors="ignore")
            score, kind, title = score_response(path, resp.status, resp.headers.get("Content-Type", ""), body)
            if kind != "unknown" and score >= 6:
                return Hit(
                    path=path,
                    url=str(resp.url),
                    status=resp.status,
                    content_type=resp.headers.get("Content-Type", ""),
                    score=score,
                    kind=kind,
                    title=title,
                )
            return None
    except (aiohttp.ClientError, asyncio.TimeoutError):
        return None


async def _run_probe(
    base_url: str,
    candidates: list[str],
    concurrency: int,
    timeout: float,
    allow_redirects: bool,
    max_bytes: int,
) -> list[Hit]:
    if aiohttp is None:
        raise RuntimeError("aiohttp is not installed")

    connector = aiohttp.TCPConnector(ssl=False)
    sem = asyncio.Semaphore(concurrency)
    hits: list[Hit] = []

    async with aiohttp.ClientSession(connector=connector) as session:
        async def bound_fetch(path: str) -> None:
            async with sem:
                hit = await _fetch_candidate(
                    session=session,
                    base_url=base_url,
                    path=path,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    max_bytes=max_bytes,
                )
                if hit:
                    hits.append(hit)

        await asyncio.gather(*(bound_fetch(path) for path in candidates))

    hits.sort(key=lambda h: (h.score, h.kind.startswith("openapi"), h.status), reverse=True)
    return hits


def probe_swagger_hits(
    base_url: str,
    discovered_paths: Iterable[str] | None = None,
    timeout: float = 7.0,
    concurrency: int = 25,
    allow_redirects: bool = True,
    max_bytes: int = 200_000,
    only_openapi: bool = False,
    only_ui: bool = False,
) -> list[Hit]:
    """Return all likely Swagger/OpenAPI hits (score >= 3), sorted best-first."""
    if aiohttp is None:
        return []

    validated = validate_base_url(base_url)
    candidates = build_candidate_paths(
        discovered_paths=discovered_paths,
        only_openapi=only_openapi,
        only_ui=only_ui,
    )
    if not candidates:
        return []
    return asyncio.run(
        _run_probe(
            base_url=validated,
            candidates=candidates,
            concurrency=concurrency,
            timeout=timeout,
            allow_redirects=allow_redirects,
            max_bytes=max_bytes,
        )
    )


def find_swagger_url_entry(
    base_url: str,
    discovered_paths: Iterable[str] | None = None,
    timeout: float = 7.0,
    concurrency: int = 25,
    allow_redirects: bool = True,
    max_bytes: int = 200_000,
    only_openapi: bool = False,
    only_ui: bool = False,
) -> Optional[str]:
    """Entry function for import usage. Returns best detected Swagger/OpenAPI URL."""
    hits = probe_swagger_hits(
        base_url=base_url,
        discovered_paths=discovered_paths,
        timeout=timeout,
        concurrency=concurrency,
        allow_redirects=allow_redirects,
        max_bytes=max_bytes,
        only_openapi=only_openapi,
        only_ui=only_ui,
    )
    if not hits:
        return None

    preferred = [h for h in hits if h.kind in {"openapi-json", "openapi-yaml"}]
    return (preferred[0] if preferred else hits[0]).url
