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

## Blocking infrastructure findings

The first executable security run found **18 failed Checkov checks**, 29 passes
and zero suppressions in the existing, unchanged Terraform laboratory. Reference:
https://github.com/Abou291/cloudshield-enterprise/actions/runs/35523843250

| Resource | Failed checks | Count |
|---|---|---|
| aws_cloudtrail.lab | CKV_AWS_252 (SNS), CKV_AWS_35 (KMS), CKV2_AWS_10 (CloudWatch integration) | 3 |
| aws_vpc.lab | CKV2_AWS_12 (default security group), CKV2_AWS_11 (flow logs) | 2 |
| aws_s3_bucket.trail | CKV_AWS_18 (access logs), CKV2_AWS_62 (notifications), CKV2_AWS_61 (lifecycle), CKV_AWS_144 (replication), CKV_AWS_145 (KMS) | 5 |
| aws_s3_bucket.vulnerable_demo | The same five S3 checks plus CKV_AWS_21 (versioning), CKV2_AWS_6 (public access block) | 7 |
| aws_security_group.vulnerable_ssh | CKV2_AWS_5 (unattached security group) | 1 |

Some resources are intentionally vulnerable and disabled by default, but that is
not a blanket exemption for the laboratory's logging infrastructure. The checks
remain enabled and blocking. No skip list, baseline suppression or soft-fail was added.

Before merging for deployment:

1. Harden the CloudTrail/logging/VPC baseline in a dedicated infrastructure increment.
2. Separate intentionally vulnerable fixtures from protective infrastructure.
3. Document any narrowly justified lab-only exception (e.g. replication cost) with
   resource scope, rationale and review date; do not broadly suppress a check.
4. Validate Terraform syntax and provider configuration, inspect an authorized plan,
   then separately authorize any deployment and cost.
5. Complete the Trivy dependency check, which originally could not run after Checkov failed.

## CI repairs

The original `trivy-action@0.28.0` tag did not exist. Its corrected old release
then depended on an unavailable setup action. The workflow now pins the verified
v0.36.0 commit, whose setup dependency is also commit-pinned. Trivy is configured
to execute even if an earlier scan fails; the earlier failure still blocks CI.

The PR remains a draft while these gates are unresolved. The application changes
are reviewable and useful for local evaluation, but are not an approved production release.
