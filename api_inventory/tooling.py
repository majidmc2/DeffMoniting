from __future__ import annotations

import asyncio
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from .inventory import Observation, observation_from_url
from .utils import RobotsPolicy, extract_urls_and_paths

LOGGER = logging.getLogger(__name__)

try:
    import aiohttp  # type: ignore
except Exception:  # pragma: no cover
    aiohttp = None

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
    ".xml",
    ".webp",
    ".mp4",
    ".mp3",
}
API_PATH_PATTERNS = (
    r"/api(?:/|$)",
    r"/apis(?:/|$)",
    r"/v[0-9]+(?:/|$)",
    r"/graphql(?:/|$)",
    r"/rest(?:/|$)",
    r"/rpc(?:/|$)",
    r"/openapi(?:/|$)",
    r"/swagger(?:/|$)",
    r"/api-docs(?:/|$)",
    r"/docs-json(?:/|$)",
)
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


@dataclass
class ToolingResult:
    observations: list[Observation]
    metadata: dict[str, Any]
    warnings: list[str]


@dataclass
class CommandResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int
    command: list[str]


def _resolve_binary(name: str, tools_dir: str | Path = "./tools") -> str | None:
    which = shutil.which(name)
    if which:
        return which

    local_dir = Path(tools_dir)
    candidates = [local_dir / name, local_dir / name.lower(), local_dir / name.capitalize()]
    if name.lower() == "xnlinkfinder":
        candidates.extend([local_dir / "xnLinkFinder", local_dir / "xnl", local_dir / "xnlinkfinder"])

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return str(candidate)
    return None


def _run_command(cmd: list[str], timeout: float, stdin_text: str | None = None) -> CommandResult:
    try:
        completed = subprocess.run(
            cmd,
            input=stdin_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return CommandResult(
            ok=completed.returncode == 0,
            stdout=completed.stdout,
            stderr=completed.stderr,
            returncode=completed.returncode,
            command=cmd,
        )
    except subprocess.TimeoutExpired as exc:
        return CommandResult(
            ok=False,
            stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
            stderr=f"timeout after {timeout}s",
            returncode=-1,
            command=cmd,
        )
    except Exception as exc:
        return CommandResult(
            ok=False,
            stdout="",
            stderr=str(exc),
            returncode=-1,
            command=cmd,
        )


def _filter_disallowed(
    values: list[str],
    robots: RobotsPolicy | None,
    user_agent: str,
    base_url: str,
) -> list[str]:
    if robots is None:
        return values
    out: list[str] = []
    for value in values:
        parsed = urlparse(value)
        if parsed.scheme and parsed.netloc:
            if robots.can_fetch(user_agent, value):
                out.append(value)
            continue
        resolved = urljoin(base_url, value)
        if robots.can_fetch(user_agent, resolved):
            out.append(value)
    return out


def _collect_observations(candidates: list[str], source: str, base_url: str) -> list[Observation]:
    out: list[Observation] = []
    for candidate in candidates:
        out.append(
            observation_from_url(
                url=candidate,
                method="UNKNOWN",
                source=source,
                evidence=f"{source}:{candidate}",
                base_url=base_url,
            )
        )
    return out


def run_katana(
    base_url: str,
    timeout: float,
    max_pages: int,
    robots: RobotsPolicy | None,
    user_agent: str,
    tools_dir: str | Path = "./tools",
) -> tuple[list[str], dict[str, Any], list[str]]:
    warnings: list[str] = []
    metadata: dict[str, Any] = {"tool": "katana", "available": False}

    binary = _resolve_binary("katana", tools_dir=tools_dir)
    if not binary:
        warnings.append("katana not found in PATH or ./tools; skipping")
        return [], metadata, warnings

    metadata["available"] = True
    cmd = [binary, "-u", base_url, "-silent"]
    if max_pages > 0:
        cmd.extend(["-c", str(min(max_pages, 50))])

    result = _run_command(cmd, timeout=timeout)
    metadata["command"] = cmd
    metadata["returncode"] = result.returncode
    if not result.ok and not result.stdout:
        warnings.append(f"katana failed: {result.stderr.strip() or 'unknown error'}")
        return [], metadata, warnings

    candidates: list[str] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        candidates.extend(extract_urls_and_paths(line))

    if robots is not None:
        candidates = _filter_disallowed(candidates, robots=robots, user_agent=user_agent, base_url=base_url)

    deduped = sorted(set(candidates))
    if max_pages > 0:
        deduped = deduped[:max_pages]
    metadata["candidate_count"] = len(deduped)
    if result.stderr.strip():
        metadata["stderr"] = result.stderr.strip()[:4000]
    return deduped, metadata, warnings


def run_subjs(
    base_url: str,
    timeout: float,
    tools_dir: str | Path = "./tools",
) -> tuple[list[str], dict[str, Any], list[str]]:
    warnings: list[str] = []
    metadata: dict[str, Any] = {"tool": "subjs", "available": False}

    binary = _resolve_binary("subjs", tools_dir=tools_dir)
    if not binary:
        warnings.append("subjs not found in PATH or ./tools; skipping")
        return [], metadata, warnings

    metadata["available"] = True
    first_try = _run_command([binary, "-u", base_url], timeout=timeout)
    if not first_try.ok and not first_try.stdout.strip():
        second_try = _run_command([binary], timeout=timeout, stdin_text=f"{base_url}\n")
        result = second_try
        metadata["command"] = [binary, "<stdin>"]
    else:
        result = first_try
        metadata["command"] = [binary, "-u", base_url]

    metadata["returncode"] = result.returncode
    if not result.ok and not result.stdout:
        warnings.append(f"subjs failed: {result.stderr.strip() or 'unknown error'}")
        return [], metadata, warnings

    js_urls: list[str] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("http://") or line.startswith("https://"):
            js_urls.append(line)

    js_urls = sorted(set(js_urls))
    metadata["js_url_count"] = len(js_urls)
    if result.stderr.strip():
        metadata["stderr"] = result.stderr.strip()[:4000]
    return js_urls, metadata, warnings


def run_xnlinkfinder(
    target_inputs: list[str],
    timeout: float,
    robots: RobotsPolicy | None,
    user_agent: str,
    tools_dir: str | Path = "./tools",
) -> tuple[list[str], dict[str, Any], list[str]]:
    warnings: list[str] = []
    metadata: dict[str, Any] = {"tool": "xnlinkfinder", "available": False}

    binary = _resolve_binary("xnLinkFinder", tools_dir=tools_dir) or _resolve_binary("xnlinkfinder", tools_dir=tools_dir)
    if not binary:
        warnings.append("xnLinkFinder not found in PATH or ./tools; skipping")
        return [], metadata, warnings

    metadata["available"] = True
    endpoints: list[str] = []
    commands: list[list[str]] = []

    for target in target_inputs[:25]:
        cmd = [binary, "-i", target, "-o", "cli"]
        result = _run_command(cmd, timeout=timeout)
        commands.append(cmd)
        if not result.ok and "-o" in (result.stderr or ""):
            cmd = [binary, "-i", target]
            result = _run_command(cmd, timeout=timeout)
            commands.append(cmd)

        if not result.ok and not result.stdout:
            warnings.append(f"xnLinkFinder failed for {target}: {result.stderr.strip() or 'unknown error'}")
            continue

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            endpoints.extend(extract_urls_and_paths(line))

    if robots is not None:
        base_for_robots = target_inputs[0] if target_inputs else ""
        endpoints = _filter_disallowed(endpoints, robots=robots, user_agent=user_agent, base_url=base_for_robots)

    deduped = sorted(set(endpoints))
    metadata["command_count"] = len(commands)
    metadata["candidate_count"] = len(deduped)
    metadata["commands"] = commands[:10]
    return deduped, metadata, warnings


def discover_with_tools(
    base_url: str,
    timeout: float,
    max_pages: int,
    include_tools: bool,
    robots: RobotsPolicy | None,
    user_agent: str,
    tools_dir: str | Path = "./tools",
) -> ToolingResult:
    metadata: dict[str, Any] = {"enabled": include_tools, "runs": []}
    warnings: list[str] = []
    observations: list[Observation] = []

    if not include_tools:
        return ToolingResult(observations=observations, metadata=metadata, warnings=warnings)

    katana_urls, katana_meta, katana_warn = run_katana(
        base_url=base_url,
        timeout=timeout,
        max_pages=max_pages,
        robots=robots,
        user_agent=user_agent,
        tools_dir=tools_dir,
    )
    metadata["runs"].append(katana_meta)
    warnings.extend(katana_warn)
    observations.extend(_collect_observations(katana_urls, source="katana", base_url=base_url))

    js_urls, subjs_meta, subjs_warn = run_subjs(base_url=base_url, timeout=timeout, tools_dir=tools_dir)
    metadata["runs"].append(subjs_meta)
    warnings.extend(subjs_warn)
    observations.extend(_collect_observations(js_urls, source="subjs", base_url=base_url))

    xnl_targets = [base_url] + js_urls[:20]
    xnl_candidates, xnl_meta, xnl_warn = run_xnlinkfinder(
        target_inputs=xnl_targets,
        timeout=timeout,
        robots=robots,
        user_agent=user_agent,
        tools_dir=tools_dir,
    )
    metadata["runs"].append(xnl_meta)
    warnings.extend(xnl_warn)
    observations.extend(_collect_observations(xnl_candidates, source="xnlinkfinder", base_url=base_url))

    return ToolingResult(observations=observations, metadata=metadata, warnings=warnings)
