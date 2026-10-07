#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../backend"
python -m PyInstaller --noconfirm --clean --onefile --name aegisshield-api --collect-data app --collect-all awscrt --hidden-import _awscrt --paths . app/desktop.py
