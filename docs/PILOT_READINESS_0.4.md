# AegisShield 0.4 pilot readiness

## Automated evidence

The exact release candidate must pass:
- frontend lint, tests and production build;
- backend tests on SQLite and PostgreSQL with the configured coverage threshold;
- secret scan, SAST, IaC scan and filesystem vulnerability scan;
- Python and npm dependency audit;
- CycloneDX SBOM generation;
- Windows PyInstaller backend build and packaged demo scan;
- packaged Electron shell startup and secured loopback backend health;
- NSIS installer generation and SHA-256 checksum.

## Runtime controls implemented

- loopback-only packaged API;
- random per-launch bearer token and backend instance nonce;
- production API documentation disabled;
- production trusted-host restriction and request-body limit;
- RBAC and server-selected tenant identity;
- read-only AWS STS AssumeRole with External ID/account binding and named SSO profile;
- fail-soft AWS collector coverage with explicit coverage-gap findings;
- local database backup/restore with SQLite integrity checks;
- diagnostics and safe AWS error classification;
- machine-readable report export with deterministic SHA-256 integrity checksum;
- Aegis Copilot is read-only and receives bounded, sanitized finding context.

## External blockers before unrestricted customer production

These cannot be truthfully completed by repository code alone:
- run the installer on representative physical Windows endpoints and validate endpoint-protection compatibility;
- validate against real AWS pilot accounts and real IAM Identity Center sessions;
- obtain a trusted Windows code-signing certificate and configure repository signing secrets;
- create the first signed tagged release and verify Authenticode/SmartScreen behavior;
- perform independent penetration testing and remediate material findings;
- exercise backup/restore and incident response with a real operator;
- confirm CRA classification/conformity route and actual GDPR controller/processor obligations for the commercial deployment.

No checkbox or document in the repository substitutes for those external activities.
