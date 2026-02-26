# API Inventory

Production-oriented Python tooling to inventory and diff a web app's API interactions for targets you own or are explicitly authorized to test.

## Features

- Swagger/OpenAPI discovery.
- OpenAPI JSON/YAML parsing into endpoint DTO inventory records.
- Optional static discovery pipeline via:
  - `katana`
  - `subjs`
  - `xnLinkFinder`
- Optional dynamic runtime capture via Playwright (XHR/fetch request+response metadata).
- Schema inference for JSON request/response bodies.
- Versioned inventory persistence and automatic diffing.

## Install

```bash
bash setup.sh
```

What `setup.sh` does:

- Creates `./tools` and tries to install `katana`, `subjs`, and `xnLinkFinder` there.
- Creates `.venv` and installs Python dependencies from `requirements.txt`.
- Attempts Playwright Chromium install for dynamic capture.

## Usage

```bash
python3 main.py https://example.com
```

Example with options:

```bash
python3 main.py https://example.com \
  --out-dir ./api_inventory \
  --concurrency 30 \
  --timeout 15 \
  --max-pages 30 \
  --max-depth 2 \
  --include-tools \
  --include-playwright \
  --headers "X-Test: 1" \
  --cookies "session=abc" \
  --max-body-bytes 200000
```

Swagger-only run:

```bash
python3 main.py https://example.com --only-swagger --no-playwright --no-tools
```

## Output

Per host outputs are written under:

```text
./api_inventory/<host>/
```

Each run writes:

- `inventory_<YYYYmmdd_HHMMSS>.json`
- If previous exists:
  - `diff_<prev>__<new>.json`
  - `diff_<prev>__<new>.md`

## Notes

- Secrets are redacted by default. Use `--no-redact` to disable.
- `robots.txt` is respected by default. Disable with `--no-respect-robots`.
- Missing optional tools/dependencies never crash the run; they are skipped with warnings.
