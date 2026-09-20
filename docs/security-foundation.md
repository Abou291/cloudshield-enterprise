# Security foundation — v0.2

This increment hardens the V1 prototype. It is not a production certification,
an OIDC implementation, or a distributed scan platform.

## What changed

- Every data endpoint derives tenant identity from a server-configured API key.
- The server stores SHA-256 hashes of high-entropy random tokens, never the raw tokens.
  This is NOT a password hashing scheme. Do not use human-chosen passwords as tokens.
- Viewers can read; operators can scan. No tenant identifier supplied by a client is trusted.
- Findings are keyed by tenant, source and fingerprint. Demo and AWS data cannot overwrite each other.
- Scan history and audit reads are scoped by tenant, including direct scan-ID lookups.
- A durable database lock serializes scans within each tenant. Different tenants have different locks.
- Success atomically commits findings, history and audit. Failure preserves the previous findings.
- AWS scans require a tenant-specific role, ExternalId and expected account ID. The API cannot
  fall back to ambient AWS credentials to scan an unconfigured tenant.
- Demo mode rejects AWS scans entirely, and production configuration rejects demo mode.
- AWS SDK calls have bounded retries and socket timeouts. These are not a total scan deadline.
- Network checks understand TCP ranges, all-protocol rules and IPv6. This is rule exposure,
  not proof of end-to-end network reachability.
- The dashboard labels synthetic data, separates sources and shows history and failures.
  It no longer gives an unscanned environment a 100/100 security score.

## Local demonstration

`docker compose up --build` explicitly runs demo mode and binds host ports to
127.0.0.1. The fixture contains synthetic insecure resources. Demo access has no
authentication: do not expose this deployment via a public proxy or tunnel.
Compose is a local demo configuration, not a production deployment manifest.

## Authenticated evaluation

From `backend`, generate a token locally:

```sh
python -m app.admin generate-key --tenant company-a --subject analyst-1 --role operator
```

The command displays the token once and a configuration entry containing its hash.
Keep the token in a password manager. Configure the server with a JSON list of
the generated entries, for example via a deployment secret/environment manager:

```text
CLOUDSHIELD_ENV=production
CLOUDSHIELD_DEMO_MODE=false
CLOUDSHIELD_API_KEYS=[<generated JSON entry>]
CLOUDSHIELD_CORS_ORIGINS=["https://your-console.example"]
```

The placeholder above is not runnable JSON; use the actual generated entry.
Use TLS at your reverse proxy. API clients use `Authorization: Bearer <token>`.
The console keeps the token in memory, not localStorage/sessionStorage; a reload
or sign-out forgets it. A browser compromise can still steal an in-memory token.
Sign-out is not server-side revocation. To revoke, remove the hash and restart all
API instances; rotate by issuing a new token. There is no expiry or key-management API yet.

One principal belongs to one tenant. Issue separate keys when a person needs
multiple organizations. Never ship raw API tokens in frontend environment variables.
No API keys are committed in this repository.

## AWS binding

Set `CLOUDSHIELD_AWS_CONNECTIONS` to a JSON object keyed by tenant:

```json
{
  "company-a": {
    "role_arn": "arn:aws:iam::123456789012:role/cloudshield-readonly",
    "external_id": "replace-with-a-unique-external-id",
    "account_id": "123456789012",
    "region": "eu-west-3"
  }
}
```

Provision a read-only role with an ExternalId condition and a trust policy scoped
to the collector identity. The bootstrap identity only needs to assume approved
roles. Collector and remediation roles must remain separate; no remediation
role is implemented. The caller identity after AssumeRole must match account_id.
Role ARN and configured account must also match at startup.

The previous global `CLOUDSHIELD_AWS_ROLE_ARN` setting is retained for compatibility
but is no longer used by the HTTP scan endpoint. See security-model.md for actions.
Do not configure AWS in the local demo Compose deployment.

## Safe database upgrade

Back up the existing database first. At startup, new tables `tenant_findings`,
`scan_runs`, `scan_locks` and `audit_events` are created additively.
The old V1 `findings` table is left untouched and is not read by the new API.
It has no trustworthy tenant ownership, so assigning it automatically would be unsafe.
Run a new scan to populate the new tables; a deliberately reviewed import is a future task.
The console may therefore initially appear empty after upgrade, while old data still exists.

Rolling back to V1 restores access to the legacy table, but V1 will not show new
v0.2 scans or findings. Do not run both versions against a shared public deployment.
Schema evolution still uses create_all, not a general migration framework.

## Interrupted scan recovery

If the API process is killed, its lock deliberately remains. A later request gets
409 instead of starting a potentially overlapping scan. No automatic expiry is
used because it could permit two active collectors. Recovery is local maintenance:

1. Stop ALL API/scanner instances and verify no scan remains active.
2. Back up the database and identify the exact tenant and running scan ID.
3. From backend, using that database configuration, run:

```sh
python -m app.admin recover-scan --tenant company-a --scan-id EXACT_ID --confirm-scanners-stopped
```

4. Restart the API. Verify the scan is interrupted and the audit event is present.

The command atomically matches tenant, scan ID and running state, preserves findings,
and records recovery. Never recover an active scan.

## Explicit limitations and next gates

- Scans remain synchronous and suitable only for small evaluation accounts. Reverse-proxy
  timeouts do not necessarily cancel collection. Durable worker orchestration is next.
- Tenant isolation is enforced in application queries and composite keys, not PostgreSQL RLS.
- Audit records have no HTTP mutation route but are NOT immutable against database administrators.
- No SSO/MFA, per-user sessions, distributed rate limiting or trusted reverse-proxy config is supplied.
- Health is liveness only, not database readiness or collector freshness.
- Findings absent from a later scan are NOT automatically resolved; no complete-coverage
  reconciliation exists. Successful collection of supported APIs does not mean a complete AWS audit.
- IAM checks see direct AdministratorAccess attachments, not effective IAM permissions,
  groups, inline policies, permission boundaries or organization policies.
- S3 public-policy status is not a full ACL/Block Public Access exposure analysis.
- Encryption configuration presence is not proof of data classification or key suitability.
- EC2 collection covers one configured region; S3/IAM use their supported account scopes.
- No CloudTrail ingestion, attack-path proof, automated remediation or compliance certification.
- Before an external pilot: independent security review, OIDC, RLS, queue/recovery design,
  explicit migrations, TLS/ingress quotas, restore exercises and real sandbox validation.
