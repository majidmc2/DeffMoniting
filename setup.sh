#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${ROOT_DIR}/tools"
VENV_DIR="${ROOT_DIR}/.venv"
REQ_FILE="${ROOT_DIR}/requirements.txt"

KATANA_URL="https://github.com/projectdiscovery/katana/releases/download/v1.4.0/katana_1.4.0_linux_amd64.zip"
SUBJS_URL="https://github.com/lc/subjs/releases/download/v1.0.1/subjs_1.0.1_linux_amd64.tar.gz"
XNL_URL="https://github.com/xnl-h4ck3r/xnLinkFinder/archive/refs/tags/v8.1.tar.gz"

log() {
  printf '[setup] %s\n' "$1"
}

warn() {
  printf '[setup][warn] %s\n' "$1" >&2
}

die() {
  printf '[setup][error] %s\n' "$1" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

linux_amd64_guard() {
  local os arch
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  arch="$(uname -m)"
  [[ "${os}" == "linux" ]] || warn "Detected OS '${os}'. Script targets Linux releases."
  [[ "${arch}" == "x86_64" || "${arch}" == "amd64" ]] || warn "Detected arch '${arch}'. Script targets amd64 releases."
}

extract_archive() {
  local archive url tmpdir
  archive="$1"
  url="$2"
  tmpdir="$3"

  if [[ "${url}" == *.zip ]]; then
    require_cmd unzip
    unzip -q "${archive}" -d "${tmpdir}"
    return 0
  fi

  if [[ "${url}" == *.tar.gz || "${url}" == *.tgz ]]; then
    require_cmd tar
    tar -xzf "${archive}" -C "${tmpdir}"
    return 0
  fi

  return 1
}

install_binary_from_url() {
  local label target_bin url binary_hint
  label="$1"
  target_bin="$2"
  url="$3"
  binary_hint="$4"

  if [[ -x "${target_bin}" ]]; then
    log "${label} already installed at ${target_bin}"
    return 0
  fi

  local archive tmpdir found
  archive="$(mktemp)"
  tmpdir="$(mktemp -d)"

  log "Downloading ${label} from ${url}"
  if ! curl -fsSL "${url}" -o "${archive}"; then
    rm -f "${archive}"
    rm -rf "${tmpdir}"
    warn "Failed to download ${label}"
    return 1
  fi

  if ! extract_archive "${archive}" "${url}" "${tmpdir}"; then
    rm -f "${archive}"
    rm -rf "${tmpdir}"
    warn "Unsupported archive format for ${label}: ${url}"
    return 1
  fi

  found="$(find "${tmpdir}" -type f \( -name "${binary_hint}" -o -name "${binary_hint}.exe" \) | head -n 1 || true)"
  if [[ -z "${found}" ]]; then
    rm -f "${archive}"
    rm -rf "${tmpdir}"
    warn "Could not find binary '${binary_hint}' for ${label}"
    return 1
  fi

  install -m 0755 "${found}" "${target_bin}"

  rm -f "${archive}"
  rm -rf "${tmpdir}"
  log "Installed ${label} to ${target_bin}"
  return 0
}

install_xnlinkfinder_from_url() {
  local wrapper_path script_path req_copy
  wrapper_path="${TOOLS_DIR}/xnLinkFinder"
  script_path="${TOOLS_DIR}/xnLinkFinder.py"
  req_copy="${TOOLS_DIR}/xnLinkFinder.requirements.txt"

  if [[ -x "${wrapper_path}" && -f "${script_path}" ]]; then
    log "xnLinkFinder already installed at ${wrapper_path}"
    patch_xnlinkfinder_script "${script_path}"
    return 0
  fi

  local archive tmpdir found_script found_req
  archive="$(mktemp)"
  tmpdir="$(mktemp -d)"

  log "Downloading xnLinkFinder source from ${XNL_URL}"
  if ! curl -fsSL "${XNL_URL}" -o "${archive}"; then
    rm -f "${archive}"
    rm -rf "${tmpdir}"
    warn "Failed to download xnLinkFinder source"
    return 1
  fi

  if ! extract_archive "${archive}" "${XNL_URL}" "${tmpdir}"; then
    rm -f "${archive}"
    rm -rf "${tmpdir}"
    warn "Unsupported archive format for xnLinkFinder"
    return 1
  fi

  found_script="$(find "${tmpdir}" -type f -name "xnLinkFinder.py" | head -n 1 || true)"
  if [[ -z "${found_script}" ]]; then
    rm -f "${archive}"
    rm -rf "${tmpdir}"
    warn "Could not find xnLinkFinder.py inside source archive"
    return 1
  fi

  install -m 0644 "${found_script}" "${script_path}"

  found_req="$(find "${tmpdir}" -type f -name "requirements.txt" | head -n 1 || true)"
  if [[ -n "${found_req}" ]]; then
    install -m 0644 "${found_req}" "${req_copy}"
  fi

  cat >"${wrapper_path}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
  exec "${ROOT_DIR}/.venv/bin/python" -W ignore "${ROOT_DIR}/tools/xnLinkFinder.py" "$@"
fi
exec python3 -W ignore "${ROOT_DIR}/tools/xnLinkFinder.py" "$@"
EOF

  chmod +x "${wrapper_path}"
  patch_xnlinkfinder_script "${script_path}"

  rm -f "${archive}"
  rm -rf "${tmpdir}"
  log "Installed xnLinkFinder to ${wrapper_path}"
  return 0
}

patch_xnlinkfinder_script() {
  local script_path
  script_path="$1"
  [[ -f "${script_path}" ]] || return 0

  python3 - "${script_path}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

old = "try:\n    from . import __version__\nexcept Exception:\n    pass\n"
new = "try:\n    from . import __version__\nexcept Exception:\n    __version__ = \"8.1\"\n"

if old in text:
    text = text.replace(old, new, 1)
elif "__version__" not in text:
    insert_at = text.find("# Try to import lxml")
    if insert_at != -1:
        text = text[:insert_at] + "__version__ = \"8.1\"\n\n" + text[insert_at:]

path.write_text(text, encoding="utf-8")
PY
}

setup_python_env() {
  require_cmd python3

  if [[ ! -d "${VENV_DIR}" ]]; then
    log "Creating virtual environment at ${VENV_DIR}"
    python3 -m venv "${VENV_DIR}"
  else
    log "Virtual environment already exists at ${VENV_DIR}"
  fi

  # shellcheck disable=SC1090
  source "${VENV_DIR}/bin/activate"

  log "Upgrading pip"
  python -m pip install --upgrade pip >/dev/null

  [[ -f "${REQ_FILE}" ]] || die "Missing requirements.txt at ${REQ_FILE}"

  log "Installing Python dependencies"
  python -m pip install -r "${REQ_FILE}"

  if [[ -f "${TOOLS_DIR}/xnLinkFinder.requirements.txt" ]]; then
    log "Installing xnLinkFinder Python dependencies"
    python -m pip install -r "${TOOLS_DIR}/xnLinkFinder.requirements.txt" || warn "xnLinkFinder dependency install failed"
  fi

  if python -c 'import playwright' >/dev/null 2>&1; then
    log "Installing Playwright Chromium browser"
    python -m playwright install chromium || warn "Playwright browser install failed; dynamic capture may be unavailable"
  fi
}

main() {
  require_cmd curl
  linux_amd64_guard

  mkdir -p "${TOOLS_DIR}"

  install_binary_from_url "katana" "${TOOLS_DIR}/katana" "${KATANA_URL}" "katana" || warn "katana installation skipped"
  install_binary_from_url "subjs" "${TOOLS_DIR}/subjs" "${SUBJS_URL}" "subjs" || warn "subjs installation skipped"
  install_xnlinkfinder_from_url || warn "xnLinkFinder installation skipped"

  setup_python_env

  log "Setup complete"
  log "Activate your environment with: source .venv/bin/activate"
}

main "$@"
