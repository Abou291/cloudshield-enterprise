# Security foundation validation

Validation performed on 2026-09-20. This report records observed results, not a
security certification or a claim of zero vulnerabilities.

## Application

- 42 backend tests pass locally: measured line coverage 94%.
- Backend CI passes on SQLite and PostgreSQL 16.
- 5 frontend tests, ESLint, TypeScript and Vite build pass locally and in CI.
- Ruff and git diff --check pass.
- GitHub Gitleaks passes.
- GitHub Semgrep runs 263 rules on 31 targets with zero findings in the configured rulesets.
- No real AWS credentials, scans, Terraform deployment or customer data were used.

## Infrastructure validation

The first executable security run found 18 failed Checkov checks in the original
Terraform laboratory. Reference:
https://github.com/Abou291/cloudshield-enterprise/actions/runs/35523843250

The lab baseline was then hardened with:

- a rotating KMS key with constrained CloudTrail, CloudWatch, SNS and S3 grants;
- KMS encryption for trail storage, log groups and the security-events topic;
- CloudTrail delivery to CloudWatch, log-file validation and SNS notification;
- VPC flow logs and a restricted default security group;
- bucket versioning, lifecycle retention, incomplete-upload cleanup and notifications;
- at least one year of CloudWatch audit-log retention.

The successful security run reports **126 passed, 0 failed and 13 skipped Checkov
checks**. Gitleaks, Semgrep and Trivy also pass. Reference:
https://github.com/Abou291/cloudshield-enterprise/actions/runs/35524442689

The 13 inline exceptions are resource-specific and reviewable: ten cover the
disabled-by-default negative-test S3/security-group fixtures, two cover access
logging recursion and cross-region replication in the isolated cost-bounded trail
bucket, and three cover the AWS requirement that KMS key policies use `Resource: "*"`.
The KMS grants remain constrained by principals, source account/ARN and encryption
context. No global skip list or soft-fail is configured.

No Terraform plan or apply was run. Before deploying the lab, inspect a plan in
the dedicated account, verify the external trust/KMS policies and authorize the
AWS cost separately. Passing static checks does not prove runtime correctness.

## CI repairs

The original `trivy-action@0.28.0` tag did not exist. Its corrected old release
then depended on an unavailable setup action. The workflow now pins the verified
v0.36.0 commit, whose setup dependency is also commit-pinned. Trivy is configured
to execute even if an earlier scan fails; the earlier failure still blocks CI.

All configured CI gates now pass. This validates the reviewed repository state;
it does not make the prototype an approved production service. The limitations in
`security-foundation.md` still apply.
