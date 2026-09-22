# AegisShield threat model

## Security objectives
Protect customer cloud metadata, tenant boundaries, credentials, findings and audit evidence while ensuring the scanner and Copilot cannot silently change customer infrastructure.

## Trust boundaries
1. Browser/desktop UI -> AegisShield API.
2. API -> database.
3. Scanner -> customer AWS account through temporary STS credentials.
4. API -> optional external AI provider.
5. CI/release pipeline -> distributable artifacts.

## High-value assets
AWS role configuration and temporary credentials; tenant identity; findings and resource metadata; audit records; AI context; signing/release credentials.

## Primary threats and required controls
- **Credential theft:** never persist long-lived AWS access keys; redact secrets; production secret manager; short-lived STS sessions.
- **Broken tenant isolation / IDOR:** tenant ID comes from authenticated identity, never client-controlled authorization context; authorization tests on every object endpoint.
- **Privilege escalation:** least-privilege roles and explicit RBAC; deny-by-default production configuration.
- **Injection / SSRF:** typed validation, fixed provider endpoints in production, no arbitrary URL/shell tool exposed to Copilot.
- **Prompt injection:** cloud evidence is untrusted data; bounded context; no write tools; no secret access.
- **Supply-chain compromise:** pinned CI actions, dependency audit, secret/SAST/IaC/container scans, SBOM and signed releases.
- **DoS:** request limits, scan quotas/timeouts and bounded AI context; load testing before production.
- **Tampering:** immutable/append-oriented audit trail target, signed releases and integrity validation.
- **Data leakage to AI provider:** external AI opt-in; minimize/redact context; contractual/privacy review before customer use.

## Residual risks before customer production
Independent pentest, tenant-isolation test campaign, AWS IAM review, production secret-manager deployment, encrypted backup/restore exercise, signed installer/update channel, load testing and incident-response exercise remain release blockers.
