output "role_arn" {
  description = "The ARN of the IAM role created for Odineyes"
  value       = aws_iam_role.odineyes_readonly.arn
}

output "external_id" {
  description = "The External ID used in the trust policy"
  value       = var.external_id
}

output "onboarding_status" {
  description = "The result of the auto-connect API call to Odineyes"
  value       = data.external.odineyes_autoconnect.result["status"]
}
