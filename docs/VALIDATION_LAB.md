# Validation lab: proving detections on a real AWS account

Until a scan has run against a real account, the detections are only unit-tested. This lab closes that gap in about fifteen minutes and costs nothing: it creates an empty bucket and an unattached security group with known weaknesses, scans them, and checks that every expected rule fires.

> Use a disposable AWS account or sandbox. Never deploy this stack in an account that hosts a workload.

## 1. Deploy the misconfigured stack

```bash
aws cloudformation deploy \
  --stack-name aegisshield-validation-lab \
  --template-file infra/aws/validation-lab.yaml \
  --parameter-overrides VpcId=<default-vpc-id>
```

Expected weaknesses: partial S3 Block Public Access, no bucket logging, no versioning, no TLS-deny policy (tagged `Environment=prod`, `DataClassification=confidential`), and a security group open to the world on 22, 5432 and 6379.

## 2. Deploy the read-only scanner role

Deploy `infra/aws/aegisshield-readonly-role.yaml` (see the README pilot flow), or use a profile with the `ReadOnlyAccess` managed policy for a quick lab run.

## 3. Run the offline scan

```bash
cd backend
pip install -e .
python -m app.cli --profile <profile> --region <region> \
  --output lab-report.json \
  --expect S3-003,S3-004,S3-005,S3-006,NET-001,NET-004,NET-007
```

The command exits non-zero if an expected rule did not fire, prints extra detections without failing, and writes `lab-report.json` (findings, risk breakdown with context provenance, attack-path candidates, compliance posture, coverage gaps and context coverage).

Add `--anonymize` before sharing the report: account and resource identifiers are replaced by stable hashes and the evidence payload is dropped.

## 4. What to check in the report

- `findings[].risk.reasons` shows `Production asset +15 (tag Environment=prod)` and `Sensitive data +18 (tag DataClassification=confidential)` on the lab bucket: context comes from the real tags.
- `coverage_gaps` is empty. A non-empty list means a permission is missing in the scanner role, which is the intended fail-soft behaviour.
- `compliance` lists the failing CIS and AWS FSBP controls linked to those rules.

## 5. Clean up

```bash
aws cloudformation delete-stack --stack-name aegisshield-validation-lab
```

## What this does and does not prove

It proves that the collectors, the context derivation and the rules work against real AWS APIs for these resources. It does not measure false-positive rates on a production estate or coverage of services outside the AWS coverage matrix; repeat the scan on at least one real, tagged environment and record the result in `docs/validation-results.md`.

## Running it from GitHub Actions (no key stored anywhere)

1. In the sandbox account, deploy `infra/aws/github-oidc-role.yaml` (CloudFormation console, or `aws cloudformation deploy --capabilities CAPABILITY_NAMED_IAM`). Set `CreateOidcProvider=false` if the GitHub OIDC provider already exists.
2. Copy the `RoleArn` output into a repository **variable** (not a secret) named `AWS_VALIDATION_ROLE_ARN` (Settings, Secrets and variables, Actions, Variables).
3. Run the **Validation lab** workflow from the Actions tab and pick the region.

The workflow assumes the role through OIDC, deploys the lab stack, scans it with the real collectors, checks the expected rules, publishes a short summary as annotations plus an anonymized report artifact, and always deletes the stack.
