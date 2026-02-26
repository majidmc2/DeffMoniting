from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .inventory import Observation, now_iso
from .utils import RobotsPolicy, cap_body_bytes, is_probable_api_path, normalize_url_forms, path_params_from_template

LOGGER = logging.getLogger(__name__)

try:
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    from playwright.async_api import async_playwright
except Exception:  # pragma: no cover
    async_playwright = None
    PlaywrightTimeoutError = Exception


@dataclass
class PlaywrightResult:
    observations: list[Observation]
    metadata: dict[str, Any]
    warnings: list[str]


def is_playwright_available() -> bool:
    return async_playwright is not None


def _parse_cookie_header(cookie_header: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for part in cookie_header.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        value = value.strip()
        if name:
            out.append((name, value))
    return out


async def _capture_async(
    base_url: str,
    timeout: float,
    max_pages: int,
    max_depth: int,
    user_agent: str,
    extra_headers: dict[str, str] | None,
    cookie_header: str | None,
    max_body_bytes: int,
    robots: RobotsPolicy | None,
) -> PlaywrightResult:
    metadata: dict[str, Any] = {
        "enabled": True,
        "visited_pages": [],
        "captured_events": 0,
    }
    warnings: list[str] = []
    observations: list[Observation] = []

    if async_playwright is None:
        return PlaywrightResult(
            observations=[],
            metadata={"enabled": False},
            warnings=["playwright is not installed; skipping dynamic capture"],
        )

    host = (urlparse(base_url).hostname or "").lower()
    queue: list[tuple[str, int]] = [(base_url, 0)]
    seen_pages: set[str] = set()

    body_sem = asyncio.Semaphore(4)
    pending_tasks: set[asyncio.Task[Any]] = set()

    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path="/usr/bin/chromium", headless=True)
        context = await browser.new_context(
            user_agent=user_agent,
            extra_http_headers=extra_headers or {},
            ignore_https_errors=True,
        )

        if cookie_header:
            cookies = _parse_cookie_header(cookie_header)
            if cookies and host:
                await context.add_cookies(
                    [{"name": k, "value": v, "domain": host, "path": "/"} for k, v in cookies]
                )

        page = await context.new_page()

        async def on_response(response: Any) -> None:
            request = response.request
            if getattr(request, "resource_type", "") not in {"xhr", "fetch"}:
                return

            req_url = request.url
            if robots is not None and not robots.can_fetch(user_agent, req_url):
                return

            async with body_sem:
                try:
                    req_headers = await request.all_headers()
                except Exception:
                    req_headers = getattr(request, "headers", {}) or {}

                try:
                    resp_headers = await response.all_headers()
                except Exception:
                    resp_headers = getattr(response, "headers", {}) or {}

                req_post_data = getattr(request, "post_data", None)
                try:
                    body_bytes = await response.body()
                except Exception:
                    body_bytes = b""

                forms = normalize_url_forms(req_url)
                if not is_probable_api_path(forms.path):
                    return

                observations.append(
                    Observation(
                        method=(request.method or "GET").upper(),
                        absolute_url=forms.absolute,
                        path=forms.path,
                        host=forms.host,
                        query_params=forms.query_params,
                        path_params=path_params_from_template(forms.path),
                        request_headers={str(k): str(v) for k, v in req_headers.items()},
                        request_content_type=str(req_headers.get("content-type", "")),
                        request_body=req_post_data,
                        response_status=getattr(response, "status", None),
                        response_headers={str(k): str(v) for k, v in resp_headers.items()},
                        response_content_type=str(resp_headers.get("content-type", "")),
                        response_body=cap_body_bytes(body_bytes, max_body_bytes),
                        source="playwright",
                        evidence=f"playwright:{request.method} {forms.absolute}",
                        timestamp=now_iso(),
                    )
                )

        def response_listener(response: Any) -> None:
            task = asyncio.create_task(on_response(response))
            pending_tasks.add(task)
            task.add_done_callback(lambda t: pending_tasks.discard(t))

        page.on("response", response_listener)

        while queue and len(seen_pages) < max_pages:
            next_url, depth = queue.pop(0)
            if next_url in seen_pages:
                continue
            if depth > max_depth:
                continue
            if robots is not None and not robots.can_fetch(user_agent, next_url):
                continue

            seen_pages.add(next_url)
            metadata["visited_pages"].append(next_url)

            try:
                await page.goto(next_url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
                await page.wait_for_timeout(600)
            except PlaywrightTimeoutError:
                warnings.append(f"playwright timeout visiting {next_url}")
                continue
            except Exception as exc:
                warnings.append(f"playwright failed visiting {next_url}: {exc}")
                continue

            if depth >= max_depth:
                continue

            try:
                links = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
            except Exception:
                links = []

            for link in links:
                if not isinstance(link, str):
                    continue
                parsed = urlparse(link)
                if parsed.scheme not in {"http", "https"}:
                    continue
                if (parsed.hostname or "").lower() != host:
                    continue
                if link in seen_pages:
                    continue
                queue.append((link, depth + 1))

        if pending_tasks:
            await asyncio.gather(*pending_tasks, return_exceptions=True)

        metadata["captured_events"] = len(observations)

        await context.close()
        await browser.close()

    return PlaywrightResult(observations=observations, metadata=metadata, warnings=warnings)


def capture_with_playwright(
    base_url: str,
    include_playwright: bool,
    timeout: float,
    max_pages: int,
    max_depth: int,
    user_agent: str,
    extra_headers: dict[str, str] | None,
    cookie_header: str | None,
    max_body_bytes: int,
    robots: RobotsPolicy | None,
) -> PlaywrightResult:
    if not include_playwright:
        return PlaywrightResult(observations=[], metadata={"enabled": False}, warnings=[])

    if async_playwright is None:
        return PlaywrightResult(
            observations=[],
            metadata={"enabled": False},
            warnings=["playwright is not installed; skipping dynamic capture"],
        )

    return asyncio.run(
        _capture_async(
            base_url=base_url,
            timeout=timeout,
            max_pages=max_pages,
            max_depth=max_depth,
            user_agent=user_agent,
            extra_headers=extra_headers,
            cookie_header=cookie_header,
            max_body_bytes=max_body_bytes,
            robots=robots,
        )
    )
