variable "aws_region" {
  description = "Dedicated lab region."
  type        = string
  default     = "eu-west-3"
}

variable "budget_email" {
  description = "Email address that receives cost alerts."
  type        = string
  sensitive   = true
}

variable "monthly_budget_usd" {
  description = "Hard reminder threshold; AWS Budgets does not automatically stop resources."
  type        = number
  default     = 10
}

variable "enable_vulnerable_lab" {
  description = "Creates deliberate misconfigurations in an isolated account. Keep false by default."
  type        = bool
  default     = false
}

variable "audit_retention_days" {
  description = "Retention for isolated-lab CloudTrail and VPC flow logs."
  type        = number
  default     = 30

  validation {
    condition     = contains([30, 60, 90, 120, 150, 180, 365], var.audit_retention_days)
    error_message = "Use a CloudWatch-supported retention period of at least 30 days."
  }
}
