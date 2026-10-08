provider "aws" {
  region = "us-east-1"
}

module "odineyes_org" {
  source = "../.."

  organizational_unit_id      = "ou-1234-abcd5678"
  regions                     = ["us-east-1", "eu-west-1"]
  
  # This template URL should be hosted somewhere accessible to CloudFormation
  # Odineyes provides this template during the onboarding process
  cloudformation_template_url = "https://example.com/template.json"
  
  odineyes_api_url       = "https://api.odineyes.example.com"
  odineyes_api_key       = "your-api-key"
  odineyes_api_secret    = "your-api-secret"
}

output "stack_set_name" {
  value = module.odineyes_org.stack_set_name
}
