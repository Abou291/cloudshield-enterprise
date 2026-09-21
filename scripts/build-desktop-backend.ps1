$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location "$root/backend"
python -m PyInstaller --noconfirm --clean --onefile --name aegisshield-api --collect-data app --paths . app/desktop.py
