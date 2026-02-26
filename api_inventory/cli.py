from __future__ import annotations

import argparse
import asyncio
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .diff import diff_inventories, render_diff_markdown
from .inventory import build_inventory_document, consolidate_observations, now_iso
from .playwright_capture import capture_with_playwright
from .swagger_ingest import collect_from_swagger
from .tooling import discover_with_tools
from .utils import fetch_robots_policy, parse_header_kv

LOGGER = logging.getLogger(__name__)


def _ensure_url(value: str) -> str:
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    parsed = urlparse(value)
    if not parsed.netloc:
        raise ValueError(f"Invalid target URL: {value}")
    return value


def _inventory_timestamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=False)


def _latest_inventory_file(host_dir: Path) -> Path | None:
    candidates = sorted(host_dir.glob("inventory_*.json"))
    if not candidates:
        return None
    return candidates[-1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 main.py",
        description="Inventory and diff API interactions for authorized targets.",
    )
    parser.add_argument("target_url", help="Target base URL (must be authorized).")
    parser.add_argument("--out-dir", default="./api_inventory", help="Output directory for inventories.")
    parser.add_argument("--concurrency", type=int, default=25, help="Concurrency for swagger probing.")
    parser.add_argument("--timeout", type=float, default=12.0, help="Timeout in seconds.")
    parser.add_argument("--max-pages", type=int, default=20, help="Max pages to crawl/visit.")
    parser.add_argument("--max-depth", type=int, default=2, help="Max navigation depth for Playwright.")

    parser.add_argument("--include-playwright", dest="include_playwright", action="store_true", default=True)
    parser.add_argument("--no-playwright", dest="include_playwright", action="store_false")

    parser.add_argument("--include-tools", dest="include_tools", action="store_true", default=True)
    parser.add_argument("--no-tools", dest="include_tools", action="store_false")

    parser.add_argument("--only-swagger", action="store_true", help="Run only swagger discovery/ingestion.")
    parser.add_argument("--no-redact", action="store_true", help="Disable secret redaction.")

    parser.add_argument("--respect-robots", dest="respect_robots", action="store_true", default=True)
    parser.add_argument("--no-respect-robots", dest="respect_robots", action="store_false")

    parser.add_argument("--user-agent", default="api-inventory/1.0")
    parser.add_argument("--headers", action="append", default=[], help='Repeatable custom headers: "K: V"')
    parser.add_argument("--cookies", default="", help='Cookie header string: "k=v; k2=v2"')
    parser.add_argument("--max-body-bytes", type=int, default=200_000, help="Max bytes for body sampling.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return parser


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def run(args: argparse.Namespace) -> int:
    _configure_logging(args.log_level)

    target_url = _ensure_url(args.target_url)
    target_host = (urlparse(target_url).hostname or "unknown-host").lower()
    out_root = Path(args.out_dir).resolve()
    host_dir = out_root / target_host

    headers = parse_header_kv(args.headers)
    started_at = now_iso()

    robots_policy = None
    if args.respect_robots:
        robots_policy = asyncio.run(
            fetch_robots_policy(
                base_url=target_url,
                timeout=args.timeout,
                user_agent=args.user_agent,
                headers=headers,
            )
        )

    all_observations = []
    warnings: list[str] = []

    tooling_result = None
    playwright_result = None

    if not args.only_swagger:
        tooling_result = discover_with_tools(
            base_url=target_url,
            timeout=args.timeout,
            max_pages=args.max_pages,
            include_tools=args.include_tools,
            robots=robots_policy if args.respect_robots else None,
            user_agent=args.user_agent,
            tools_dir="./tools",
        )
        all_observations.extend(tooling_result.observations)
        warnings.extend(tooling_result.warnings)

    discovered_paths = [obs.path for obs in all_observations if getattr(obs, "path", "")]
    swagger_result = collect_from_swagger(
        base_url=target_url,
        timeout=args.timeout,
        concurrency=args.concurrency,
        user_agent=args.user_agent,
        headers=headers,
        discovered_paths=discovered_paths,
    )
    all_observations.extend(swagger_result.observations)
    warnings.extend(swagger_result.warnings)

    if not args.only_swagger:
        playwright_result = capture_with_playwright(
            base_url=target_url,
            include_playwright=args.include_playwright,
            timeout=args.timeout,
            max_pages=args.max_pages,
            max_depth=args.max_depth,
            user_agent=args.user_agent,
            extra_headers=headers,
            cookie_header=args.cookies or None,
            max_body_bytes=args.max_body_bytes,
            robots=robots_policy if args.respect_robots else None,
        )
        all_observations.extend(playwright_result.observations)
        warnings.extend(playwright_result.warnings)

    redact_enabled = not args.no_redact
    endpoints = consolidate_observations(
        observations=all_observations,
        redact=redact_enabled,
        max_body_bytes=args.max_body_bytes,
    )

    metadata: dict[str, Any] = {
        "config": {
            "concurrency": args.concurrency,
            "timeout": args.timeout,
            "max_pages": args.max_pages,
            "max_depth": args.max_depth,
            "include_playwright": args.include_playwright,
            "include_tools": args.include_tools,
            "only_swagger": args.only_swagger,
            "redaction_enabled": redact_enabled,
            "respect_robots": args.respect_robots,
            "user_agent": args.user_agent,
            "max_body_bytes": args.max_body_bytes,
        },
        "swagger": swagger_result.metadata,
        "tools": tooling_result.metadata if tooling_result else {"enabled": False},
        "playwright": playwright_result.metadata if playwright_result else {"enabled": False},
        "warnings": warnings,
    }

    completed_at = now_iso()
    inventory_doc = build_inventory_document(
        target_url=target_url,
        endpoints=endpoints,
        metadata=metadata,
        started_at=started_at,
        completed_at=completed_at,
    )

    previous_file = _latest_inventory_file(host_dir)
    timestamp = _inventory_timestamp()
    inventory_file = host_dir / f"inventory_{timestamp}.json"
    _write_json(inventory_file, inventory_doc)

    print(f"Inventory written: {inventory_file}")
    print(f"Endpoints discovered: {len(endpoints)}")

    if warnings:
        print(f"Warnings: {len(warnings)}")
        for warning in warnings[:10]:
            print(f" - {warning}")

    if previous_file and previous_file.exists():
        previous_doc = _load_json(previous_file)
        diff_result = diff_inventories(previous_doc, inventory_doc)

        prev_stamp = previous_file.stem.replace("inventory_", "")
        new_stamp = inventory_file.stem.replace("inventory_", "")

        diff_file = host_dir / f"diff_{prev_stamp}__{new_stamp}.json"
        _write_json(diff_file, diff_result)

        md_file = host_dir / f"diff_{prev_stamp}__{new_stamp}.md"
        md_file.write_text(render_diff_markdown(diff_result), encoding="utf-8")

        summary = diff_result.get("summary", {})
        print(
            "Diff summary: "
            f"added={summary.get('added', 0)} "
            f"removed={summary.get('removed', 0)} "
            f"changed={summary.get('changed', 0)}"
        )
        print(f"Diff written: {diff_file}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
