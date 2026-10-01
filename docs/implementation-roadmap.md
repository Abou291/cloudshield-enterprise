# Evidence-driven next increments

AegisShield 0.7 adds conservative executive risk correlation on top of the existing
AWS CSPM pipeline. Attack-path candidates are explicitly **not** proof of network,
credential, or exploit reachability; they are prioritization signals derived from
multiple independent findings.

| Priority | Increment | Status / acceptance evidence |
|---|---|---|
| P0 | Current security foundation | Implemented: tenant isolation, failed-scan preservation, RBAC, additive upgrades |
| P0 | AWS posture inventory | Implemented: IAM/S3/EC2/RDS/CloudTrail/GuardDuty/Security Hub/Config/KMS/Lambda/ECR/Secrets/EKS/ELB plus multi-region option |
| P0 | Risk intelligence | Implemented in 0.7: executive summary, exposure/privilege/sensitive-data correlation, candidate attack paths, regression tests |
| P1 | OIDC, revocation and PostgreSQL RLS | Issuer/audience validation, token expiry, database-level cross-tenant tests |
| P1 | Versioned migrations and restoration | Upgrade fixtures, backup restoration with measured outcome |
| P1 | Durable workers and scan orchestration | Worker termination, retries, duplicate delivery, backpressure and cancellation |
| P1 | Coverage-aware inventory outcomes | PASS/FAIL/UNKNOWN/ERROR semantics and explicit permission-denied accounting |
| P2 | Relationship-backed attack graph | Persist resource relationships and prove narrow IAM/network reachability with sandbox fixtures |
| P2 | CloudTrail event pipeline | Schema validation, deduplication, delayed events and tested correlations |
| P2 | Terraform remediation PRs | Bound approvals, revalidation on drift and post-change verification |
| P3 | External pilot readiness | Independent audit, load results, operating cost, support and incident runbooks |

Do not present candidate attack paths as verified exploit chains. The intended product
flow is discovery -> evidence -> prioritization -> reviewed correction, including a
visible collection failure mode and an honest coverage result.
