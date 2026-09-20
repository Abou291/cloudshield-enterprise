data "aws_caller_identity" "current" {}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_budgets_budget" "lab" {
  name         = "cloudshield-lab-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_email]
  }
}

resource "aws_s3_bucket" "trail" {
  # Access logging would require a second logging bucket and recursively raises the
  # same requirement. CloudTrail data events and object notifications cover access here.
  #checkov:skip=CKV_AWS_18:CloudTrail data events and notifications are the audit controls for this dedicated trail bucket.
  # Cross-region replication adds a second region and material lab cost. Versioning,
  # retention and recovery are kept in-region for this isolated, disposable lab.
  #checkov:skip=CKV_AWS_144:Single-region isolated lab; cross-region recovery is outside this cost-bounded environment.
  bucket        = "cloudshield-trail-${data.aws_caller_identity.current.account_id}-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_kms_key" "trail" {
  description             = "CloudShield isolated lab audit-log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.trail_kms.json
}

resource "aws_kms_alias" "trail" {
  name          = "alias/cloudshield-lab-${random_id.suffix.hex}"
  target_key_id = aws_kms_key.trail.key_id
}

data "aws_iam_policy_document" "trail_kms" {
  # KMS key policies require Resource "*" because the policy is attached to this
  # exact key. Access is bounded by named service principals, SourceArn/account
  # and encryption-context conditions below; the account-root statement only
  # delegates administration to IAM policies in this isolated account.
  #checkov:skip=CKV_AWS_109:KMS key-policy Resource must be star; principals and conditions scope every grant.
  #checkov:skip=CKV_AWS_111:KMS key-policy Resource must be star; write access is principal/condition constrained.
  #checkov:skip=CKV_AWS_356:KMS key policies cannot name their own key ARN as Resource.
  statement {
    sid       = "AccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

  statement {
    sid       = "CloudTrailEncryption"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${var.aws_region}:${data.aws_caller_identity.current.account_id}:trail/cloudshield-lab"]
    }
  }

  statement {
    sid = "CloudWatchLogsEncryption"
    actions = [
      "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"
    ]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/cloudshield/lab/*"]
    }
  }

  statement {
    sid       = "SecurityEventEncryption"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com", "s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.trail.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail" {
  bucket = aws_s3_bucket.trail.id
  rule {
    id     = "expire-lab-audit-data"
    status = "Enabled"
    expiration { days = var.audit_retention_days }
    noncurrent_version_expiration { noncurrent_days = var.audit_retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_sns_topic" "security_events" {
  name              = "cloudshield-lab-security-events"
  kms_master_key_id = aws_kms_key.trail.id
}

data "aws_iam_policy_document" "security_events" {
  statement {
    sid       = "CloudTrailPublish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_events.arn]
    principals { type = "Service" identifiers = ["cloudtrail.amazonaws.com"] }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
  statement {
    sid       = "S3Publish"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_events.arn]
    principals { type = "Service" identifiers = ["s3.amazonaws.com"] }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_s3_bucket.trail.arn]
    }
  }
}

resource "aws_sns_topic_policy" "security_events" {
  arn    = aws_sns_topic.security_events.arn
  policy = data.aws_iam_policy_document.security_events.json
}

resource "aws_s3_bucket_notification" "trail" {
  bucket = aws_s3_bucket.trail.id
  topic {
    topic_arn = aws_sns_topic.security_events.arn
    events    = ["s3:ObjectCreated:*"]
  }
  depends_on = [aws_sns_topic_policy.security_events]
}

data "aws_iam_policy_document" "trail_bucket" {
  statement {
    sid       = "CloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals { type = "Service" identifiers = ["cloudtrail.amazonaws.com"] }
  }
  statement {
    sid       = "CloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals { type = "Service" identifiers = ["cloudtrail.amazonaws.com"] }
    condition { test = "StringEquals" variable = "s3:x-amz-acl" values = ["bucket-owner-full-control"] }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail_bucket.json
}

resource "aws_cloudtrail" "lab" {
  name                          = "cloudshield-lab"
  s3_bucket_name                = aws_s3_bucket.trail.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.trail.arn
  sns_topic_name                = aws_sns_topic.security_events.name
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_logs.arn
  depends_on                    = [aws_s3_bucket_policy.trail, aws_sns_topic_policy.security_events]
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/cloudshield/lab/cloudtrail"
  retention_in_days = var.audit_retention_days
  kms_key_id        = aws_kms_key.trail.arn
}

data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals { type = "Service" identifiers = ["cloudtrail.amazonaws.com"] }
  }
}

data "aws_iam_policy_document" "cloudtrail_logs" {
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:*"]
  }
}

resource "aws_iam_role" "cloudtrail_logs" {
  name               = "cloudshield-lab-cloudtrail-logs"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  name   = "write-cloudtrail-log-group"
  role   = aws_iam_role.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_logs.json
}

# Deliberately insecure resources exist only when explicitly enabled in an
# isolated account. Never deploy this module in production or with real data.
resource "aws_s3_bucket" "vulnerable_demo" {
  # This resource is the opt-in negative test fixture. Each exception is scoped
  # to this resource and the variable remains false by default.
  #checkov:skip=CKV_AWS_18:Intentionally missing access logging for CSPM negative testing.
  #checkov:skip=CKV2_AWS_62:Intentionally missing event notifications for CSPM negative testing.
  #checkov:skip=CKV2_AWS_61:Intentionally missing lifecycle policy for CSPM negative testing.
  #checkov:skip=CKV_AWS_21:Intentionally missing versioning for CSPM negative testing.
  #checkov:skip=CKV_AWS_144:Replication is intentionally absent from the negative-test fixture.
  #checkov:skip=CKV_AWS_145:KMS encryption is intentionally absent from the negative-test fixture.
  #checkov:skip=CKV2_AWS_6:Public-access controls are intentionally absent from the negative-test fixture.
  count         = var.enable_vulnerable_lab ? 1 : 0
  bucket        = "cloudshield-vulnerable-${data.aws_caller_identity.current.account_id}-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_vpc" "lab" {
  cidr_block           = "10.70.0.0/16"
  enable_dns_hostnames = true
}

resource "aws_default_security_group" "lab" {
  vpc_id = aws_vpc.lab.id
}

resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = "/cloudshield/lab/vpc-flow"
  retention_in_days = var.audit_retention_days
  kms_key_id        = aws_kms_key.trail.arn
}

data "aws_iam_policy_document" "flow_logs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals { type = "Service" identifiers = ["vpc-flow-logs.amazonaws.com"] }
  }
}

data "aws_iam_policy_document" "flow_logs_write" {
  statement {
    actions = [
      "logs:CreateLogGroup", "logs:CreateLogStream", "logs:DescribeLogGroups",
      "logs:DescribeLogStreams", "logs:PutLogEvents"
    ]
    resources = ["${aws_cloudwatch_log_group.vpc_flow.arn}:*"]
  }
}

resource "aws_iam_role" "flow_logs" {
  name               = "cloudshield-lab-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_logs_assume.json
}

resource "aws_iam_role_policy" "flow_logs" {
  name   = "write-vpc-flow-log-group"
  role   = aws_iam_role.flow_logs.id
  policy = data.aws_iam_policy_document.flow_logs_write.json
}

resource "aws_flow_log" "lab" {
  iam_role_arn    = aws_iam_role.flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.lab.id
}

resource "aws_security_group" "vulnerable_ssh" {
  #checkov:skip=CKV2_AWS_5:Opt-in unattached negative-test fixture; no compute workload is exposed.
  count       = var.enable_vulnerable_lab ? 1 : 0
  name        = "cloudshield-deliberately-public-ssh"
  description = "Deliberately vulnerable lab rule detected by CloudShield"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "DELIBERATELY INSECURE LAB ONLY"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
