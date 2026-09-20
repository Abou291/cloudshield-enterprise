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

