# Threat model

## Protected assets

- AWS role credentials and trust policy.
- Inventory and finding evidence.
- Rule integrity and risk weights.
- CI/CD identity and container images.
- Audit history and tenant boundaries.

## Primary threats and current controls

| Threat | Impact | Current control | Residual risk |
| --- | --- | --- | --- |
| Credential committed to Git | AWS compromise | `.gitignore`, Gitleaks, short-lived role design | Developer workstation exposure |
| Scanner role over-privileged | Broader cloud access | Documented minimal read policy | Policy drift |
| Malicious asset name/evidence | UI injection | React escaping, typed JSON responses | Future report generators need escaping |
| Rule file tampering | Findings suppressed | Versioned rules, CI; branch protection recommended | Protection settings not verified; no signed bundle |
| Cross-tenant data access | Confidentiality breach | Server-selected identity, scoped queries/composite keys, negative tests | No PostgreSQL RLS; compromise of application/DB credentials |
| Token theft | Unauthorized tenant access | Hash-only server config, memory-only browser token, scoped role | No MFA/expiry; rotate/revoke through configuration |
| Confused deputy | Wrong AWS account scanned | Configured role, ExternalId, post-assumption account check | Trust policy must be correctly provisioned outside application |
| Concurrent or interrupted scan | Inconsistent results | Durable tenant lock, atomic final transaction, explicit offline recovery | Synchronous scans; crashes require maintenance |
| Upstream error with secrets | Credential disclosure | Generic API error and safe stored error code | Infrastructure logs and future debugging need review |
| Audit tampering | Lost accountability | No HTTP edit/delete routes | DB administrators can alter records; no WORM export yet |
| Vulnerable dependency/image | Code execution | Dependabot, Trivy, Semgrep | Supply-chain compromise still possible |
| Cost abuse in lab | Unexpected charges | Budget alerts, vulnerable lab off by default | Budgets do not stop resources |

## Abuse cases excluded from V1

Automated remediation and active attack simulation are intentionally absent.
Both can cause destructive cloud changes and require approval gates, idempotency,
rollback and scoped test accounts.
