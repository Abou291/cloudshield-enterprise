# AegisShield security policy

## Supported status

AegisShield is security-sensitive software under active development. No software can be guaranteed unhackable. Production deployment requires environment-specific hardening and independent validation.

## Reporting a vulnerability

Do not open a public issue for vulnerabilities, credentials, tokens, customer data, cloud evidence, or exploit details. Use GitHub private vulnerability reporting when enabled for this repository.

If a secret is exposed, revoke and rotate it immediately; deleting it from Git history is not sufficient.

## Security invariants

- AWS access is read-only and uses STS AssumeRole; long-lived AWS credentials must not be stored by the application.
- The security copilot is read-only and cannot execute cloud remediation.
- External AI is opt-in. Only a bounded projection of findings is sent to the configured provider.
- Production mode must disable demo authentication.
- Secrets belong in a secret manager or deployment environment, never source control.
- Pull requests must pass tests, SAST, secret scanning, dependency/IaC scanning, and build checks.
- Findings and AI output are advisory evidence, not proof of compliance.

## Release requirements

Before handling production customer data: independent penetration test, threat-model review, dependency review, signed release artifacts, backup/recovery test, logging/monitoring validation, and incident-response ownership.
