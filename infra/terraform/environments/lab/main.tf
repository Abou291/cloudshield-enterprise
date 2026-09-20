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
  bucket        = "cloudshield-trail-${data.aws_caller_identity.current.account_id}-${random_id.suffix.hex}"
  force_destroy = true
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
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "trail" {
  bucket = aws_s3_bucket.trail.id
  versioning_configuration { status = "Enabled" }
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
  depends_on                    = [aws_s3_bucket_policy.trail]
}

# Deliberately insecure resources exist only when explicitly enabled in an
# isolated account. Never deploy this module in production or with real data.
resource "aws_s3_bucket" "vulnerable_demo" {
  count         = var.enable_vulnerable_lab ? 1 : 0
  bucket        = "cloudshield-vulnerable-${data.aws_caller_identity.current.account_id}-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_vpc" "lab" {
  cidr_block           = "10.70.0.0/16"
  enable_dns_hostnames = true
}

resource "aws_security_group" "vulnerable_ssh" {
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

