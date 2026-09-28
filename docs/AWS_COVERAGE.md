# AWS coverage matrix

AegisShield 0.7.0 is a read-only AWS CSPM pilot. This document describes what the scanner actually observes; it is not a claim of complete AWS, CIS, ISO 27001, PCI DSS or regulatory coverage.

## Identity

| Control | Evidence source | Finding |
| --- | --- | --- |
| Root MFA | IAM account summary | Root MFA disabled |
| Root access keys | IAM account summary | Root long-lived key present |
| IAM user MFA | IAM ListMFADevices | User without MFA |
| IAM user key age | IAM ListAccessKeys | Active key older than 90 days |
| Direct AdministratorAccess | IAM attached user policies | Direct administrator policy |
| Account password policy | IAM GetAccountPasswordPolicy | Password policy missing |
| IAM role privilege | IAM ListRoles + attached/inline role policies | Direct AdministratorAccess or unrestricted wildcard inline policy on a non-service-linked role |
| IAM group inheritance | IAM user groups + attached group policies | AdministratorAccess inherited through a group |
| IAM user inline privilege | IAM inline user policies | Allow wildcard Action on wildcard Resource |

## Storage and data

| Control | Evidence source | Finding |
| --- | --- | --- |
| S3 public policy/ACL state | S3 policy status + bucket ACL | Public bucket |
| S3 Block Public Access | S3 public access block | Protection not fully enabled |
| S3 default encryption | S3 encryption configuration | Explicit default encryption absent |
| S3 versioning | S3 versioning configuration | Versioning disabled |
| S3 server access logging | S3 logging configuration | Logging disabled |
| EBS volume encryption | EC2 DescribeVolumes | Unencrypted volume |
| EBS encryption by default | EC2 account setting | Default encryption disabled |
| EC2 metadata service | EC2 DescribeInstances | IMDSv2 session tokens not required |
| ECR repository scanning | ECR DescribeRepositories | Basic scan-on-push disabled, with enhanced-scanning caveat |
| Secrets Manager lifecycle | Secrets Manager ListSecrets | Secret unchanged >180 days without automatic rotation |
| RDS public accessibility | RDS DescribeDBInstances | Public database |
| RDS storage encryption | RDS DescribeDBInstances | Encryption disabled |
| RDS deletion protection | RDS DescribeDBInstances | Deletion protection disabled |
| RDS automated backup retention | RDS DescribeDBInstances | Backup retention is zero |
| DynamoDB recovery | DynamoDB DescribeContinuousBackups | Point-in-time recovery disabled |
| SQS encryption | SQS queue attributes | Server-side encryption not detected |
| SNS encryption | SNS topic attributes | KMS encryption not configured |

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
| EKS API endpoint | EKS cluster VPC config | Public control-plane endpoint open to world CIDR |
| EKS audit logging | EKS control-plane logging config | Audit log type disabled |
| ALB/NLB transport | ELBv2 load balancers and listeners | Internet-facing load balancer without HTTPS/TLS listener |
| CloudWatch Logs retention | CloudWatch DescribeLogGroups | No explicit retention period |
| Amazon Inspector | Inspector2 BatchGetAccountStatus | Inspector not enabled |
| Amazon Macie | Macie GetMacieSession | Macie not enabled |
| AWS Backup | Backup ListBackupPlans | No active backup plan detected |
| IAM Access Analyzer | Access Analyzer ListAnalyzers | No active analyzer in Region |
| EBS snapshot sharing | EC2 snapshot attributes | Public create-volume permission |
| RDS snapshot sharing | RDS snapshot attributes | Public restore permission |

## Cryptography and serverless

| Control | Evidence source | Finding |
| --- | --- | --- |
| KMS customer-key rotation | KMS key metadata and rotation status | Eligible symmetric key not rotating |
| Lambda Function URLs | Lambda URL configuration | AuthType NONE |

## Finding lifecycle

Successful scans reconcile current evidence against stored findings. Findings no longer observed are marked `resolved`; acknowledged findings remain acknowledged while the condition persists; and a resolved condition that reappears is reopened. Resolved history can be included explicitly from the API/dashboard.

## Failure semantics

Each service collector is fail-soft. An authorization failure, unavailable API or supported botocore service error becomes a `coverage_gap` asset and a `COV-001` finding instead of silently treating the service as secure or aborting the entire scan.

The scanner uses read-only APIs. The CloudFormation onboarding role contains the explicit read actions required by these collectors. No remediation API is called during a scan.

## Important limitations

- Regional coverage defaults to the configured AWS Region. The operator can enable all-region scanning, which discovers enabled regions with EC2 DescribeRegions and runs regional collectors in each one. IAM and S3 contain global/account-level elements and are collected once.
- A finding is evidence of a posture condition, not proof of exploitability.
- Absence of a finding is not proof of security.
- Some controls are architecture-dependent. For example, public endpoints or disabled logging can be intentional when documented and compensated elsewhere.
- AegisShield does not currently replace Security Hub, AWS Config, GuardDuty, an independent penetration test, or a formal compliance assessment.
