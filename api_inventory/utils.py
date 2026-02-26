from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib import robotparser
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None

LOGGER = logging.getLogger(__name__)

SENSITIVE_HEADER_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}

SENSITIVE_QUERY_KEYS = {
    "token",
    "access_token",
    "apikey",
    "api_key",
    "key",
    "password",
    "passwd",
    "secret",
}

JWT_LIKE_RE = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9._-]{10,}\.[a-zA-Z0-9._-]{10,}\b")
BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*\b")
URL_RE = re.compile(r"https?://[^\s'\"<>]+")
PATH_RE = re.compile(r"(?<![A-Za-z0-9_])(/[A-Za-z0-9._~%/:-]+)")
API_PATH_PATTERNS = (
    r"/(api|apis)(?:/|$)",
    r"/v[0-9]+(?:/|$)",
    r"/(graphql|rest|rpc)(?:/|$)",
    r"/(openapi|swagger|api-docs|docs-json)(?:/|$)",
)
NON_API_EXTENSIONS = {
    ".js",
    ".mjs",
    ".css",
    ".scss",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".pdf",
    ".zip",
    ".gz",
    ".txt",
    ".webp",
    ".mp4",
    ".mp3",
}


@dataclass
class UrlForms:
    absolute: str
    path: str
    host: str
    query_params: dict[str, str | None]


@dataclass
class RobotsPolicy:
    parser: robotparser.RobotFileParser | None

    def can_fetch(self, user_agent: str, url: str) -> bool:
        if not self.parser:
            return True
        try:
            return self.parser.can_fetch(user_agent, url)
        except Exception:
            return True


def parse_header_kv(values: Iterable[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in values:
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key:
            headers[key] = value
    return headers


def mask_secret(value: str) -> str:
    if not value:
        return value
    if len(value) <= 8:
        return "***REDACTED***"
    return f"{value[:3]}***REDACTED***{value[-2:]}"


def redact_text(value: str, enabled: bool = True) -> str:
    if not enabled or not value:
        return value
    value = JWT_LIKE_RE.sub("***JWT_REDACTED***", value)
    value = BEARER_RE.sub("Bearer ***REDACTED***", value)
    return value


def redact_headers(headers: dict[str, str], enabled: bool = True) -> dict[str, str]:
    if not headers:
        return {}
    if not enabled:
        return dict(headers)
    out: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADER_KEYS:
            out[key] = "***REDACTED***"
        else:
            out[key] = redact_text(str(value), enabled=True)
    return out


def redact_url(url: str, enabled: bool = True) -> str:
    if not enabled:
        return url
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    redacted_q: list[tuple[str, str]] = []
    for key, value in query:
        if key.lower() in SENSITIVE_QUERY_KEYS:
            redacted_q.append((key, "***REDACTED***"))
            continue
        redacted_q.append((key, redact_text(value, enabled=True)))
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(redacted_q, doseq=True),
            "",
        )
    )


def normalize_url_forms(url: str, base_url: str | None = None) -> UrlForms:
    if base_url:
        url = urljoin(base_url, url)
    parsed = urlparse(url)
    scheme = (parsed.scheme or "https").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        netloc = f"{host}:{port}"
    else:
        netloc = host

    path = parsed.path or "/"
    path = re.sub(r"/{2,}", "/", path)
    if not path.startswith("/"):
        path = "/" + path

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    query_params: dict[str, str | None] = {}
    for key, value in query_pairs:
        if key not in query_params:
            query_params[key] = value or None

    absolute = urlunparse((scheme, netloc, path, "", parsed.query, ""))
    return UrlForms(absolute=absolute, path=path, host=host, query_params=query_params)


def canonicalize_path(path: str) -> str:
    if not path:
        return "/"
    if not path.startswith("/"):
        path = "/" + path
    path = re.sub(r"/{2,}", "/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path


def cap_body_bytes(body: bytes | str | None, max_bytes: int) -> str | None:
    if body is None:
        return None
    if isinstance(body, str):
        encoded = body.encode("utf-8", errors="ignore")
        truncated = encoded[:max_bytes]
        text = truncated.decode("utf-8", errors="ignore")
        if len(encoded) > max_bytes:
            text += "\n...[truncated]"
        return text

    truncated = body[:max_bytes]
    try:
        text = truncated.decode("utf-8")
        if len(body) > max_bytes:
            text += "\n...[truncated]"
        return text
    except UnicodeDecodeError:
        b64 = base64.b64encode(truncated).decode("ascii")
        if len(body) > max_bytes:
            b64 += "...[truncated]"
        return b64


def is_json_content_type(content_type: str) -> bool:
    ctype = (content_type or "").lower()
    return "application/json" in ctype or ctype.endswith("+json")


def parse_json_safe(value: str | bytes | dict[str, Any] | list[Any] | None) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    try:
        return json.loads(value)
    except Exception:
        return None


def infer_json_schema(value: Any) -> dict[str, Any]:
    if value is None:
        return {"type": "null", "example": None}
    if isinstance(value, bool):
        return {"type": "boolean", "example": value}
    if isinstance(value, int) and not isinstance(value, bool):
        return {"type": "integer", "example": value}
    if isinstance(value, float):
        return {"type": "number", "example": value}
    if isinstance(value, str):
        return {"type": "string", "example": value[:500]}
    if isinstance(value, list):
        schema: dict[str, Any] = {"type": "array", "example": value[:3]}
        if value:
            item_schemas = [infer_json_schema(v) for v in value[:10]]
            unique_item_schemas: list[dict[str, Any]] = []
            seen = set()
            for item_schema in item_schemas:
                key = json.dumps(item_schema, sort_keys=True)
                if key not in seen:
                    seen.add(key)
                    unique_item_schemas.append(item_schema)
            schema["items"] = unique_item_schemas[0] if len(unique_item_schemas) == 1 else {"oneOf": unique_item_schemas}
        return schema
    if isinstance(value, dict):
        properties: dict[str, Any] = {}
        required: list[str] = []
        for key, v in value.items():
            properties[key] = infer_json_schema(v)
            if v is not None:
                required.append(key)
        return {
            "type": "object",
            "properties": properties,
            "required": sorted(required),
            "example": {k: value[k] for k in list(value.keys())[:20]},
        }
    return {"type": "string", "example": str(value)[:500]}


def infer_body_format(
    content_type: str,
    body: bytes | str | dict[str, Any] | list[Any] | None,
) -> tuple[str, dict[str, Any] | None, Any]:
    if body is None:
        return "unknown", None, None

    lowered = (content_type or "").lower()
    parsed_json = parse_json_safe(body) if (is_json_content_type(lowered) or isinstance(body, (dict, list))) else None
    if parsed_json is not None:
        return "json", infer_json_schema(parsed_json), parsed_json

    if "x-www-form-urlencoded" in lowered:
        if isinstance(body, bytes):
            body = body.decode("utf-8", errors="ignore")
        if isinstance(body, str):
            form_items = dict(parse_qsl(body, keep_blank_values=True))
            return "form", {"type": "object", "properties": {k: {"type": "string"} for k in form_items}}, form_items
        return "form", None, body

    if "multipart/form-data" in lowered:
        return "multipart", {"type": "object", "additionalProperties": True}, cap_body_bytes(body, 50_000)

    if isinstance(body, bytes):
        try:
            decoded = body.decode("utf-8")
            return "text", {"type": "string"}, decoded[:2000]
        except UnicodeDecodeError:
            return "binary", {"type": "string", "contentEncoding": "base64"}, cap_body_bytes(body, 20_000)

    if isinstance(body, str):
        if lowered.startswith("text/"):
            return "text", {"type": "string"}, body[:2000]
        return "unknown", None, body[:2000]

    return "unknown", None, body


def extract_urls_and_paths(text: str) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    out.extend(URL_RE.findall(text))
    for path in PATH_RE.findall(text):
        if path.startswith("//") or "." in path.split("/")[-1]:
            continue
        out.append(path)
    deduped: list[str] = []
    seen = set()
    for value in out:
        if value not in seen:
            seen.add(value)
            deduped.append(value)
    return deduped


def path_params_from_template(path: str) -> list[str]:
    return sorted(set(re.findall(r"{([^{}]+)}", path)))


def is_probable_api_path(path: str) -> bool:
    normalized = canonicalize_path(path).lower()
    last_segment = normalized.rsplit("/", 1)[-1]
    if "." in last_segment:
        ext = "." + last_segment.rsplit(".", 1)[-1]
        if ext in NON_API_EXTENSIONS:
            return False

    if any(re.search(pattern, normalized) for pattern in API_PATH_PATTERNS):
        return True

    # Keep extension-less paths that commonly appear as API routes.
    if "." not in last_segment:
        return True
    return False


async def fetch_robots_policy(
    base_url: str,
    timeout: float,
    user_agent: str,
    headers: dict[str, str] | None = None,
) -> RobotsPolicy:
    if aiohttp is None:
        return RobotsPolicy(parser=None)

    robots_url = urljoin(base_url if base_url.endswith("/") else f"{base_url}/", "robots.txt")
    merged_headers = {"User-Agent": user_agent}
    if headers:
        merged_headers.update(headers)

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                robots_url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                headers=merged_headers,
                allow_redirects=True,
                ssl=False,
            ) as response:
                if response.status >= 400:
                    return RobotsPolicy(parser=None)
                body = await response.text(errors="ignore")
    except (asyncio.TimeoutError, Exception):
        LOGGER.debug("robots fetch failed", extra={"robots_url": robots_url})
        return RobotsPolicy(parser=None)

    rp = robotparser.RobotFileParser()
    rp.parse(body.splitlines())
    return RobotsPolicy(parser=rp)
