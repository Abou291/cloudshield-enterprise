# Evidence-driven next increments

Each item is a separate reviewable increment, not a claim that the feature exists.

| Priority | Increment | Acceptance evidence |
|---|---|---|
| P0 | Current security foundation | Cross-tenant tests, failed-scan preservation, role tests, additive upgrade |
| P1 | OIDC, revocation and PostgreSQL RLS | Issuer/audience validation, token expiry, database-level cross-tenant tests |
| P1 | Versioned migrations and restoration | V1/v0.2 upgrade fixture, backup restoration with measured outcome |
| P1 | Durable workers and scan orchestration | Worker termination, retries, duplicate delivery, backpressure and cancellation |
| P1 | Coverage-aware inventory | Pagination, permission-denied outcomes, multi-region scope, no false deletion |
| P2 | Rule outcomes and versioned evidence | PASS/FAIL/UNKNOWN/ERROR semantics, regression fixtures, explainable evidence |
| P2 | CloudTrail event pipeline | Schema validation, deduplication, delayed events, tested correlations |
| P2 | Narrow attack-path analysis | Explicit IAM/network assumptions and sandbox-validated examples |
| P2 | Terraform remediation PRs | Bound approvals, revalidation on drift, post-change verification |
| P3 | External pilot readiness | Independent audit, load results, operating cost, support and incident runbooks |

Do not add Azure/Kubernetes/AI modules until the AWS pipeline has repeatable evidence.
The intended demo is discovery -> evidence -> prioritization -> reviewed correction,
including a deliberately induced collection failure and a visible honest result.
