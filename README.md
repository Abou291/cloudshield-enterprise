# AegisShield

AegisShield is an AWS Cloud Security Posture Management desktop pilot. It discovers a focused set of IAM, S3 and EC2 security-group configuration, evaluates declarative security rules, computes explainable contextual risk, persists findings locally and presents them in a React/Electron security console.

## Windows desktop pilot

The validated Windows pipeline builds an NSIS installer named `AegisShield-Setup-0.3.0.exe`. The packaged application has been exercised on a Windows GitHub runner: the PyInstaller backend starts successfully, a packaged demo scan completes, the Electron shell starts its secured loopback backend, renderer assets load with file-safe relative paths, and the installer is produced and uploaded as a workflow artifact.

The desktop backend binds to `127.0.0.1` only. Electron generates a fresh random bearer token and instance nonce at each launch; the token is injected into local API requests and is not persisted in the renderer. Production API docs are disabled in the packaged application.

The current installer is **unsigned**. It is appropriate for internal/pilot testing, but Windows SmartScreen may warn until a trusted code-signing certificate is configured.

See [docs/DESKTOP_PILOT.md](docs/DESKTOP_PILOT.md) for the Windows/AWS onboarding procedure.

## What is implemented

- FastAPI API with local fixture mode and real AWS read-only scanning.
- AWS STS AssumeRole with External ID, expected account binding and named AWS CLI/IAM Identity Center profile support.
- Declarative rules for IAM, S3 and network exposure.
- Explainable 0–100 contextual risk scoring.
- SQLite desktop persistence or PostgreSQL through Docker Compose.
- React/TypeScript dashboard with findings, scan history and audit trail.
- Read-only Aegis security copilot grounded in current findings.
- Hashed API tokens, viewer/operator roles and server-selected tenant identity.
- Tenant/source-isolated findings, transactional scan persistence and durable per-tenant scan locks.
- Windows Electron wrapper with sandboxing, navigation restrictions and CSP.
- GitHub Actions gates for backend SQLite/PostgreSQL tests, frontend lint/test/build, secret scanning, SAST, IaC scanning, dependency audit, Trivy and CycloneDX SBOM generation.
- Windows workflow that builds, smoke-tests and uploads the installer plus SHA-256 checksum.
- Least-privilege AWS CloudFormation role template for pilot onboarding.

## Windows + AWS pilot flow

1. Install AWS CLI v2 and configure a short-lived IAM Identity Center/SSO profile on the PC.
2. Deploy `infra/aws/aegisshield-readonly-role.yaml` in the AWS account with a unique External ID.
3. Install AegisShield and open **Connect AWS account**.
4. Enter the Role ARN, AWS Account ID, External ID, AWS profile name and default region.
5. Choose **Validate AWS role**; AegisShield performs STS AssumeRole and checks the resulting AWS Account ID.
6. Save the connection and run an AWS scan.

No long-lived AWS access key needs to be stored by AegisShield.

## Current real-AWS coverage

The scanner currently checks:

- IAM users: MFA state, active access-key age and attached `AdministratorAccess`.
- S3 buckets: public-policy status, server-side encryption and access logging.
- EC2 security groups: IPv4/IPv6 public exposure and sensitive port ranges.

This coverage is intentionally narrower than a mature enterprise CSPM. A successful scan does not prove that an AWS account is secure or compliant.

## Quick start with Docker

Requirements: Docker Desktop and Docker Compose.

```bash
cp .env.example .env
docker compose up --build
```

Open the dashboard at `http://localhost:5173` and run a demo scan. The fixture contains deliberately insecure resources and does not require AWS.

## Local development

Backend (Python 3.12+):

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
pip install -e "./backend[dev]"
cd backend
uvicorn app.main:app --reload
```

Frontend (Node.js 22 recommended):

```bash
cd frontend
npm install
npm run dev
```

## Run tests

```bash
cd backend
pytest
ruff check app tests

cd ../frontend
npm test -- --run
npm run build
```

## Security and release boundary

AegisShield is currently a controlled desktop/AWS pilot. Before customer production deployment, require a signed Windows installer/update channel, a green security gate on the exact release, broader live-AWS integration testing, backup/restore validation, independent penetration testing and completion of the release/compliance checklist.

See:

- [Security model](docs/security-model.md)
- [Threat model](docs/threat-model.md)
- [Security foundation and safe upgrade](docs/security-foundation.md)
- [Windows pilot runbook](docs/DESKTOP_PILOT.md)
- [Implementation roadmap](docs/implementation-roadmap.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
