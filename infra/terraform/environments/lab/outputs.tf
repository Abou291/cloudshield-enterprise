output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "cloudtrail_name" {
  value = aws_cloudtrail.lab.name
}

output "vulnerable_lab_enabled" {
  value = var.enable_vulnerable_lab
}

