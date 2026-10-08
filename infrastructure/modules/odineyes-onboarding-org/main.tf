resource "aws_cloudformation_stack_set" "odineyes_org" {
  name             = "odineyes-organization-onboarding"
  description      = "Odineyes Organization Onboarding StackSet"
  permission_model = "SERVICE_MANAGED"
  capabilities     = ["CAPABILITY_NAMED_IAM"]
  
  template_url = var.cloudformation_template_url

  auto_deployment {
    enabled                          = true
    retain_stacks_on_account_removal = false
  }

  operation_preferences {
    failure_tolerance_percentage = 100
    region_concurrency_type      = "PARALLEL"
    max_concurrent_percentage    = 100
  }

  parameters = {
    # If the CFN template took parameters, we would pass them here.
    # Currently, our CFN template bakes the external_id and account_id directly into the body.
  }
}

resource "aws_cloudformation_stack_set_instance" "odineyes_org_instances" {
  for_each       = toset(var.regions)
  stack_set_name = aws_cloudformation_stack_set.odineyes_org.name
  region         = each.value
  
  deployment_targets {
    organizational_unit_ids = [var.organizational_unit_id]
  }
  
  operation_preferences {
    region_concurrency_type      = "PARALLEL"
    failure_tolerance_percentage = 100
    max_concurrent_percentage    = 100
  }
}
