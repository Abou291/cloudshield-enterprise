# AegisShield

AegisShield est une application Windows d’audit des configurations AWS pour les petites équipes : identifier les mauvaises configurations, comprendre les priorités, suivre la correction et relancer un audit. L’accès AWS reste en lecture seule.

## Version 0.8 — audit AWS et interface Minimal SaaS

- Interface claire en français, bleu marine, navigation par vues et transitions discrètes (190 ms, désactivées si le système demande de réduire les animations).
- Vue d’ensemble, plan de correction, historique, connexion AWS et paramètres.
- Détail d’alerte en trois étapes : comprendre, corriger dans AWS, vérifier par un nouvel audit.
- Totaux sur toutes les alertes de la source ; rapport JSON complet, sans limite arbitraire à 500 résultats.
- Pas de fermeture automatique d’une alerte sur une ressource hors du périmètre effectivement réinspecté. Une ressource supprimée/non retrouvée reste à examiner ; un audit incomplet conserve les alertes précédentes.
- Démonstration explicite et séparée des résultats AWS. Les fonctions expérimentales de corrélation et d’assistant restent dans l’API, hors du parcours principal.

## Application Windows

Le workflow Windows produit `AegisShield-Setup-0.8.0.exe` avec backend Python embarqué et interface Electron. Il prévoit des tests du backend empaqueté puis de la vraie interface (styles, audit démo, navigation, détail, suivi et historique). Voir le résultat du workflow pour le statut de validation de chaque build.

L’installateur crée les raccourcis Bureau et menu Démarrer ; Node, Python et Docker ne sont pas requis pour utiliser le logiciel. AWS CLI reste nécessaire pour préparer le profil SSO utilisé par la connexion AWS. Les données locales sont conservées à la désinstallation et lors d’une mise à jour.

The desktop backend binds to `127.0.0.1` only. Electron generates a fresh random bearer token and instance nonce at each launch; the token is injected into local API requests and is not persisted in the renderer. Production API docs are disabled in the packaged application.

The current installer is **unsigned**. It is appropriate for internal/pilot testing, but Windows SmartScreen may warn until a trusted code-signing certificate is configured.

See [docs/DESKTOP_PILOT.md](docs/DESKTOP_PILOT.md) for the Windows/AWS onboarding procedure.

## What is implemented

- FastAPI API with local fixture mode and real AWS read-only scanning.
- AWS STS AssumeRole with External ID, expected account binding and named AWS CLI/IAM Identity Center profile support.
- Declarative rules for IAM, S3 and network exposure.
- Explainable 0–100 contextual risk scoring.
- Experimental risk-correlation API retained outside the main audit interface.
- SQLite desktop persistence or PostgreSQL through Docker Compose.
- React/TypeScript dashboard with findings, scan history and audit trail.
- Optional read-only assistant API, outside the main audit interface.
- Hashed API tokens, viewer/operator roles and server-selected tenant identity.
- Tenant/source-isolated findings, transactional scan persistence and durable per-tenant scan locks.
- Finding lifecycle reconciliation with acknowledged/resolved/reopened states and analyst controls in the dashboard.
- Windows Electron wrapper with sandboxing, navigation restrictions and CSP.
- GitHub Actions gates for backend SQLite/PostgreSQL tests, frontend lint/test/build, secret scanning, pinned-version Semgrep SAST, IaC scanning, pinned dependency audit, Trivy and CycloneDX SBOM generation.
- Windows workflow that builds, smoke-tests and uploads the installer plus SHA-256 checksum.
- Desktop diagnostics, AWS validation, SQLite backup/restore and machine-readable security-report export with integrity checksum.
- Certificate-gated tagged release workflow: public Windows releases fail closed unless an Authenticode signing certificate is configured.
- Least-privilege AWS CloudFormation role template for pilot onboarding.

## Windows + AWS pilot flow

1. Install AWS CLI v2 and configure a short-lived IAM Identity Center/SSO profile on the PC.
2. Deploy `infra/aws/aegisshield-readonly-role.yaml` in the AWS account with a unique External ID.
3. Installez AegisShield et ouvrez **Connexion AWS**.
4. Enter the Role ARN, AWS Account ID, External ID, AWS profile name and default region. Optionally enable **Scan all enabled AWS regions**.
5. Choisissez **Valider et enregistrer** : le rôle est testé avant l’enregistrement.
6. Revenez à la vue d’ensemble et cliquez sur **Lancer un audit**.

No long-lived AWS access key needs to be stored by AegisShield.

## Current real-AWS coverage

The scanner currently checks:

- IAM users: MFA state, active access-key age and attached `AdministratorAccess`.
- IAM: root MFA/root access-key posture, user MFA, access-key age and direct AdministratorAccess.
- S3: public-policy status, Block Public Access, server-side encryption, versioning and access logging.
- EC2/VPC: security-group IPv4/IPv6 exposure, EBS volume encryption, EBS encryption-by-default and VPC Flow Logs.
- RDS: public accessibility, storage encryption, deletion protection and automated-backup retention.
- CloudTrail: logging state, multi-Region configuration and log-file validation.
- GuardDuty: detector enabled/disabled state.
- Security Hub: enabled/disabled state.
- AWS Config: recorder presence and active-recording state.
- KMS: automatic rotation state for eligible customer-managed symmetric keys.
- Lambda: public Function URLs configured with `AuthType NONE`.
- IAM account password policy: presence and baseline properties.
- IAM roles: direct AdministratorAccess on non-service-linked roles.
- EC2 instances: IMDSv2 enforcement and public-IP context.
- ECR: repository basic scan-on-push posture, with explicit enhanced-scanning caveat.
- Secrets Manager: long-lived secrets without automatic rotation.
- EKS: world-open public API endpoints and control-plane audit logging.
- ALB/NLB: internet-facing load balancers without HTTPS/TLS listeners.
- Optional multi-Region scanning: discovers enabled AWS regions and runs regional collectors in each one; mono-Region remains the default.
- Coverage gaps: missing read-only permissions or unavailable optional service APIs are reported without aborting the whole scan.

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
- [AWS coverage matrix](docs/AWS_COVERAGE.md)
- [Implementation roadmap](docs/implementation-roadmap.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
