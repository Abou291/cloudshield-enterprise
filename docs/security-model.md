# Security model

## Current trust model

The default deployment remains a local anonymous demonstration, with AWS disabled.
Authenticated evaluation uses hashed random API tokens, viewer/operator roles,
tenant-scoped queries and per-tenant AWS connections. No client-provided tenant
selector is trusted. This is not SSO/MFA or database-level RLS.
See [security-foundation.md](security-foundation.md) for setup, upgrade and limitations.

## AWS access

Prefer role assumption with short-lived credentials. The scanner needs only:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "sts:GetCallerIdentity",
      "iam:ListUsers",
      "iam:ListMFADevices",
      "iam:ListAccessKeys",
      "iam:ListAttachedUserPolicies",
      "s3:ListAllMyBuckets",
      "s3:GetBucketLocation",
      "s3:GetBucketPolicyStatus",
      "s3:GetEncryptionConfiguration",
      "s3:GetBucketLogging",
      "ec2:DescribeSecurityGroups"
    ],
    "Resource": "*"
  }]
}
```

Some AWS list/describe actions cannot be resource-scoped. This does not justify
using `ReadOnlyAccess`, which is much broader than the V1 collector requires.

The bootstrap identity separately needs sts:AssumeRole for approved role ARNs.
The target trust policy must restrict the principal and require the configured
ExternalId. The API checks the assumed account against the tenant configuration
before collecting any inventory. Never grant write or secret-value read permissions.

## Secrets

- Never commit `.env`, AWS keys, Terraform state or evidence exports.
- Use GitHub OIDC for CI-to-AWS federation.
- Mask sensitive CI values and isolate production environments.
- Treat finding evidence as potentially sensitive configuration data.

## Before public deployment

The minimum gate is OIDC authentication, RBAC, server-side tenant scoping,
database row isolation tests, rate limiting, TLS, encrypted backups, immutable
audit logs and a completed external threat-model review.
