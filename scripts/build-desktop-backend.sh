#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../backend"
python -m PyInstaller --noconfirm --clean --onefile --name aegisshield-api --collect-data app --paths . app/desktop.py
