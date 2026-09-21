# AegisShield desktop edition

The desktop edition packages the React console and a local FastAPI service as a
Windows application. The service binds only to `127.0.0.1:8765`; it is not
available from the LAN. The local database is stored in the Windows user's
application-data directory.

## Build on Windows

Requirements: Python 3.12+, Node.js 20+ and npm.

```powershell
pip install -e ".\backend[dev]"
.\scripts\build-desktop-backend.ps1
cd frontend
npm install
npm run build:desktop
cd ..\desktop
npm install
npm run package:win
```

The NSIS installer is written to `desktop\dist`. This edition starts in
synthetic-data mode. A real AWS integration must retain the existing
read-only, AssumeRole/ExternalId authentication model and must never package
long-lived AWS credentials.
