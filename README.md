# CloudShield Enterprise

CloudShield is an AWS Cloud Security Posture Management prototype. This first
version discovers IAM, S3 and security-group configuration, evaluates
declarative YAML rules, computes an explainable risk score, persists findings,
and displays them in a React dashboard.

## What is implemented

- FastAPI API with a local fixture mode and an AWS read-only scanner.
- Declarative rules for IAM, S3 and network exposure.
- Explainable 0–100 contextual risk scoring.
- SQLite locally or PostgreSQL through Docker Compose.
- React/TypeScript dashboard with scan triggering and finding details.
- Unit and API tests.
- Docker images, Compose, GitHub Actions security/test pipeline.
- Terraform lab foundation with budget controls and vulnerable resources
  disabled by default.

Detection/correlation, multi-tenancy, compliance reports and automated
remediation are intentionally outside V1. Shipping all of them now would make
the security claims superficial.

## Quick start with Docker

Requirements: Docker Desktop and Docker Compose.

```bash
cp .env.example .env
docker compose up --build
```

Open:

- Dashboard: <http://localhost:5173>
- API documentation: <http://localhost:8000/docs>

Click **Run demo scan**. The local fixture contains four deliberately insecure
resources and does not require an AWS account.

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

Frontend (Node.js 20+):

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

## Scan an AWS account

CloudShield never needs write permissions for V1. Use an isolated lab account
and a read-only IAM role. Set `CLOUDSHIELD_AWS_ROLE_ARN`, or run with a local AWS
profile, then call:

```bash
curl -X POST http://localhost:8000/api/v1/scans/aws
```

The minimum permissions are documented in [docs/security-model.md](docs/security-model.md).
Do not store long-lived AWS keys in GitHub. The deployment workflow is designed
to use GitHub OIDC when deployment is added.

## Repository workflow

- `main` is protected and should remain deployable.
- Work on `feat/*`, `fix/*`, or `docs/*` branches.
- Open a pull request; tests and security checks must pass.
- Never commit `.env`, AWS credentials, Terraform state or customer data.

## Architecture and decisions

- [Architecture](docs/architecture.md)
- [Risk engine](docs/risk-engine.md)
- [Security model](docs/security-model.md)
- [Threat model](docs/threat-model.md)
- [Testing](docs/testing.md)

## Current limitations

- The scanner covers a deliberately narrow AWS surface.
- Pagination is implemented for IAM and EC2; S3 is global by AWS design.
- Findings use a deterministic fingerprint to deduplicate repeated scans.
- Authentication and tenant isolation are not yet implemented, so this version
  must not be exposed publicly.

## License

Apache-2.0. See [LICENSE](LICENSE).

