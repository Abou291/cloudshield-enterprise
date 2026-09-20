# Threat model

## Protected assets

- AWS role credentials and trust policy.
- Inventory and finding evidence.
- Rule integrity and risk weights.
- CI/CD identity and container images.
- Audit history and future tenant boundaries.

## Primary threats and current controls

| Threat | Impact | V1 control | Residual risk |
| --- | --- | --- | --- |
| Credential committed to Git | AWS compromise | `.gitignore`, Gitleaks, short-lived role design | Developer workstation exposure |
| Scanner role over-privileged | Broader cloud access | Documented minimal read policy | Policy drift |
| Malicious asset name/evidence | UI injection | React escaping, typed JSON responses | Future report generators need escaping |
| Rule file tampering | Findings suppressed | Protected branch and reviewed CI | No signed rule bundle yet |
| Cross-tenant data access | Confidentiality breach | Not marketed as multi-tenant | Public SaaS deployment prohibited |
| Vulnerable dependency/image | Code execution | Dependabot, Trivy, Semgrep | Supply-chain compromise still possible |
| Cost abuse in lab | Unexpected charges | Budget alerts, vulnerable lab off by default | Budgets do not stop resources |

## Abuse cases excluded from V1

Automated remediation and active attack simulation are intentionally absent.
Both can cause destructive cloud changes and require approval gates, idempotency,
rollback and scoped test accounts.

