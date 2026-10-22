#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -x .venv/bin/python ]] || { echo 'Run ./linux/install.sh first.' >&2; exit 1; }
exec .venv/bin/python run_cli.py
