$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location "$root/backend"
python -m PyInstaller --noconfirm --clean --onefile --name aegisshield-api --collect-data app --collect-all awscrt --hidden-import _awscrt --copy-metadata aegisshield-api --paths . app/desktop.py
