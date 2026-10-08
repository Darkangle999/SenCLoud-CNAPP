output "stack_set_name" {
  description = "Name of the CloudFormation StackSet"
  value       = aws_cloudformation_stack_set.odineyes_org.name
}

output "stack_set_id" {
  description = "ID of the CloudFormation StackSet"
  value       = aws_cloudformation_stack_set.odineyes_org.id
}
