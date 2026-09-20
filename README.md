# CloudShield Enterprise

CloudShield is an AWS Cloud Security Posture Management prototype. This
security-foundation release discovers IAM, S3 and security-group configuration, evaluates
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
- Hashed API tokens, viewer/operator roles and server-selected tenant identity.
- Tenant/source-isolated findings, persisted scan history and audit events.
- Transactional failure handling and a durable per-tenant scan lock.
- AWS role/ExternalId/account binding; AWS disabled in anonymous demo mode.
- IAM pagination and network checks for port ranges and IPv6.
- An honest empty state, source selector, scan history and audit trail in the console.

Detection/correlation, OIDC, database RLS, distributed workers, compliance reports
and automated remediation remain outside this release. Application-level tenant
isolation is implemented and tested; it is not yet an enterprise identity platform.

**Upgrading V1:** existing unscoped findings are preserved in their original table,
but not assigned to a tenant automatically. Read the
[upgrade and security guide](docs/security-foundation.md) before updating.

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

CloudShield does not need AWS write permissions. AWS HTTP scans now require
authenticated mode and a server-configured connection for the caller's tenant.
Follow [token and connection setup](docs/security-foundation.md). Use an isolated
lab account, read-only role and short-lived bootstrap credentials, then call:

```bash
curl -X POST http://localhost:8000/api/v1/scans/aws -H "Authorization: Bearer $CLOUDSHIELD_TOKEN"
```

The minimum permissions are documented in [docs/security-model.md](docs/security-model.md).
Do not store long-lived AWS keys in GitHub. The deployment workflow is designed
to use GitHub OIDC when deployment is added.

## Repository workflow

- Configure protection for `main`; it should remain deployable. Documentation alone does not enable protection.
- Work on `feat/*`, `fix/*`, or `docs/*` branches.
- Open a pull request; tests and security checks must pass.
- Never commit `.env`, AWS credentials, Terraform state or customer data.

## Architecture and decisions

- [Architecture](docs/architecture.md)
- [Risk engine](docs/risk-engine.md)
- [Security model](docs/security-model.md)
- [Threat model](docs/threat-model.md)
- [Testing](docs/testing.md)
- [Security foundation and safe upgrade](docs/security-foundation.md)
- [Implementation roadmap](docs/implementation-roadmap.md)

## Current limitations

- The scanner covers a deliberately narrow AWS surface.
- Pagination is implemented for IAM, EC2 and bucket enumeration.
- Findings deduplicate by tenant, source and deterministic fingerprint.
- Scans remain synchronous; interrupted processes require explicit lock recovery.
- API tokens are a pilot foundation, not SSO/MFA. Audit is not tamper-proof against DB administrators.
- The default Compose deployment is anonymous local demo mode, bound to loopback.
- No public-production or compliance claim is made. See the full limitation list in the upgrade guide.

## License

Apache-2.0. See [LICENSE](LICENSE).
