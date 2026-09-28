# AWS coverage matrix

AegisShield 0.5.0 is a read-only AWS CSPM pilot. This document describes what the scanner actually observes; it is not a claim of complete AWS, CIS, ISO 27001, PCI DSS or regulatory coverage.

## Identity

| Control | Evidence source | Finding |
| --- | --- | --- |
| Root MFA | IAM account summary | Root MFA disabled |
| Root access keys | IAM account summary | Root long-lived key present |
| IAM user MFA | IAM ListMFADevices | User without MFA |
| IAM user key age | IAM ListAccessKeys | Active key older than 90 days |
| Direct AdministratorAccess | IAM attached user policies | Direct administrator policy |
| Account password policy | IAM GetAccountPasswordPolicy | Password policy missing |

## Storage and data

| Control | Evidence source | Finding |
| --- | --- | --- |
| S3 public policy state | S3 policy status | Public bucket |
| S3 Block Public Access | S3 public access block | Protection not fully enabled |
| S3 default encryption | S3 encryption configuration | Explicit default encryption absent |
| S3 versioning | S3 versioning configuration | Versioning disabled |
| S3 server access logging | S3 logging configuration | Logging disabled |
| EBS volume encryption | EC2 DescribeVolumes | Unencrypted volume |
| EBS encryption by default | EC2 account setting | Default encryption disabled |
| RDS public accessibility | RDS DescribeDBInstances | Public database |
| RDS storage encryption | RDS DescribeDBInstances | Encryption disabled |
| RDS deletion protection | RDS DescribeDBInstances | Deletion protection disabled |
| RDS automated backup retention | RDS DescribeDBInstances | Backup retention is zero |

## Network, logging and detection

| Control | Evidence source | Finding |
| --- | --- | --- |
| World-open SSH/RDP | EC2 security-group ingress | Internet-exposed administrative port |
| VPC Flow Logs | EC2 DescribeFlowLogs | VPC without active flow log |
| CloudTrail logging | CloudTrail status | Logging disabled |
| CloudTrail multi-Region | CloudTrail trail metadata | Trail not multi-Region |
| CloudTrail file validation | CloudTrail trail metadata | Validation disabled |
| GuardDuty | GuardDuty detector state | Detector disabled |
| Security Hub | Security Hub subscription state | Hub disabled |
| AWS Config | Recorder and recorder status | No active recorder |

## Cryptography and serverless

| Control | Evidence source | Finding |
| --- | --- | --- |
| KMS customer-key rotation | KMS key metadata and rotation status | Eligible symmetric key not rotating |
| Lambda Function URLs | Lambda URL configuration | AuthType NONE |

## Failure semantics

Each service collector is fail-soft. An authorization failure, unavailable API or supported botocore service error becomes a `coverage_gap` asset and a `COV-001` finding instead of silently treating the service as secure or aborting the entire scan.

The scanner uses read-only APIs. The CloudFormation onboarding role contains the explicit read actions required by these collectors. No remediation API is called during a scan.

## Important limitations

- Regional coverage defaults to the configured AWS Region. The operator can enable all-region scanning, which discovers enabled regions with EC2 DescribeRegions and runs regional collectors in each one. IAM and S3 contain global/account-level elements and are collected once.
- A finding is evidence of a posture condition, not proof of exploitability.
- Absence of a finding is not proof of security.
- Some controls are architecture-dependent. For example, public endpoints or disabled logging can be intentional when documented and compensated elsewhere.
- AegisShield does not currently replace Security Hub, AWS Config, GuardDuty, an independent penetration test, or a formal compliance assessment.
