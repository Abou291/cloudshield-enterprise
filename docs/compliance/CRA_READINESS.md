# Cyber Resilience Act readiness

> Engineering evidence tracker, not a legal certification.

AegisShield is being prepared as a product with digital elements under Regulation (EU) 2024/2847. Final product classification and the applicable conformity-assessment route must be confirmed before commercial release.

## Essential cybersecurity evidence

| Area | AegisShield control / evidence | Status |
|---|---|---|
| Cybersecurity risk assessment | `docs/security/THREAT_MODEL.md` and this tracker | Implemented baseline; review per release |
| Secure by default | Production auth required; read-only cloud access; restrictive browser headers | Partial |
| Known exploitable vulnerabilities | CI SAST, dependency, filesystem, secret and IaC scanning | Automated gate; release review still required |
| Attack surface reduction | Read-only scanner, bounded API, CSP/security headers, non-root backend container | Partial |
| Access control | Tenant-aware identity/repositories and RBAC architecture | Needs independent authorization/IDOR test |
| Confidentiality | No long-lived AWS keys by design; secrets excluded from Git | Needs production secret-manager validation |
| Integrity | CI gates and dependency automation | Release artifact signing still required |
| Availability | API rate limiting | Needs load/DoS, backup and recovery testing |
| Security logging | Existing audit-event capability | Needs retention/alerting validation |
| Security updates | SECURITY.md policy baseline | Signed updater and operational SLA required |
| Vulnerability handling | SECURITY.md + automated scanners | Coordinated disclosure and reporting runbook required |
| SBOM | Required by release plan | Machine-readable SBOM generation/release artifact still required |

## Technical documentation set

The release dossier should contain: intended purpose and supported versions; architecture/data-flow diagrams; security assumptions; threat model and risk assessment; dependency/SBOM evidence; test reports; vulnerability handling process; secure installation/configuration/user instructions; support period; release/update process; applicable standards/specifications; conformity route and, when legally appropriate, EU declaration of conformity.

## Release rule

No document in this repository may state that AegisShield is CRA compliant, CE marked, independently audited, penetration-tested, or certified until the corresponding external/legal step has actually occurred.
