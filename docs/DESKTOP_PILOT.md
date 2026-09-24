# AegisShield Windows pilot

This guide is for a controlled AWS pilot. It is not a claim of certification or production accreditation.

## Install AegisShield

The Windows build workflow produces an NSIS installer named AegisShield-Setup-<version>.exe. The current CI artifact is intentionally unsigned until a code-signing certificate is configured, so Windows SmartScreen may warn during internal testing.

The desktop application binds its API to 127.0.0.1 only, generates a fresh random API bearer token at every launch, injects that token inside Electron rather than exposing it to the UI, stores its SQLite database under the application's user-data directory, stores AWS role metadata rather than AWS access keys, disables production API docs, and denies Electron permission requests and external window creation.

## Prepare an AWS bootstrap identity

Use AWS CLI v2 with short-lived credentials, preferably IAM Identity Center (SSO). Verify the profile with: aws sts get-caller-identity --profile YOUR_PROFILE

AegisShield uses the standard AWS credential chain on the PC and then calls STS AssumeRole. Do not create an IAM access key specifically for AegisShield.

## Create a unique External ID

PowerShell example: $ExternalId = "aegisshield-" + [guid]::NewGuid().ToString()

Keep the value available for both the role deployment and the AegisShield connection screen.

## Deploy the read-only role

Use infra/aws/aegisshield-readonly-role.yaml.

TrustedPrincipalArn must be the IAM user or role authorized to bootstrap AssumeRole. For IAM Identity Center, use the provisioned IAM role ARN rather than an STS assumed-role session ARN. The bootstrap principal must also be allowed to call sts:AssumeRole for the created scanner role.

Deploy with AWS CloudFormation using stack name aegisshield-readonly, the template above, CAPABILITY_NAMED_IAM, TrustedPrincipalArn and the generated ExternalId.

## Connect from the application

Open Connect AWS account and enter the Role ARN, 12-digit AWS Account ID, the same External ID, the local AWS profile name (for example default or company-sso), and the default AWS region. Choose Validate AWS role first. Validation performs STS AssumeRole and verifies that the resulting caller identity belongs to the configured account. Then save the connection and run an AWS scan.

## Current real-AWS coverage

The scanner currently inspects IAM users, MFA state, active access-key age and attached AdministratorAccess; S3 bucket public-policy status, encryption and access logging; and EC2 security-group IPv4/IPv6 exposure.

This is intentionally narrower than a mature CSPM. A successful scan does not prove that the AWS account is secure or compliant.

## Pilot exit criteria

Before customer production deployment, require a green Security Gate on the exact release, a signed Windows installer/update channel, backup/restore testing, broader AWS integration testing, an independent penetration test, and the legal/compliance checks in docs/compliance/RELEASE_SECURITY_CHECKLIST.md.
