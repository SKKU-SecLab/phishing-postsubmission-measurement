#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${REPO_ROOT}/.venv"
REQUIREMENTS_FILE="${REPO_ROOT}/requirements.txt"

PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "[artifact] Repository: ${REPO_ROOT}"
echo "[artifact] Python: ${PYTHON_BIN}"

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
    echo "[error] ${PYTHON_BIN} was not found."
    echo "[error] Install Python 3.9 or later and retry."
    exit 1
fi

"${PYTHON_BIN}" - <<'PY'
import sys

minimum = (3, 9)
current = sys.version_info[:2]

if current < minimum:
    raise SystemExit(
        f"Python {minimum[0]}.{minimum[1]} or later is required; "
        f"found {current[0]}.{current[1]}."
    )

print(f"[artifact] Python version: {sys.version.split()[0]}")
PY

if [[ ! -f "${REQUIREMENTS_FILE}" ]]; then
    echo "[error] Missing requirements file: ${REQUIREMENTS_FILE}"
    exit 1
fi

if [[ ! -d "${VENV_DIR}" ]]; then
    echo "[artifact] Creating virtual environment: ${VENV_DIR}"
    "${PYTHON_BIN}" -m venv "${VENV_DIR}"
else
    echo "[artifact] Reusing virtual environment: ${VENV_DIR}"
fi

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

python -m pip install --upgrade pip setuptools wheel
python -m pip install -r "${REQUIREMENTS_FILE}"

echo "[artifact] Verifying required Python packages..."

python - <<'PY'
required = {
    "accelerate": "accelerate",
    "bs4": "beautifulsoup4",
    "hdbscan": "hdbscan",
    "numpy": "numpy",
    "openai": "openai",
    "selenium": "selenium",
    "sklearn": "scikit-learn",
    "tldextract": "tldextract",
    "torch": "torch",
    "tqdm": "tqdm",
    "transformers": "transformers",
}

failed = []

for module, package in required.items():
    try:
        __import__(module)
        print(f"[ok] {package}")
    except Exception as exc:
        failed.append((package, str(exc)))
        print(f"[failed] {package}: {exc}")

if failed:
    names = ", ".join(name for name, _ in failed)
    raise SystemExit(f"Dependency verification failed: {names}")
PY

echo
echo "[artifact] Installation completed successfully."
echo "[artifact] Activate the environment with:"
echo "           source \"${VENV_DIR}/bin/activate\""
echo
echo "[artifact] Evaluation instructions:"
echo "           ${REPO_ROOT}/README.md (see the Usage section)"