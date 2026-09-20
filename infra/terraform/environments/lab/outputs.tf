output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "cloudtrail_name" {
  value = aws_cloudtrail.lab.name
}

output "vulnerable_lab_enabled" {
  value = var.enable_vulnerable_lab
}

output "security_events_topic_arn" {
  description = "SNS topic receiving CloudTrail and trail-bucket object notifications."
  value       = aws_sns_topic.security_events.arn
}
