provider "aws" {
  region = "us-east-1"
}

module "odineyes_onboarding" {
  source = "../.."

  # These values should come from the Odineyes UI when adding a new account
  odineyes_account_id       = "999999999999" # Replace with actual Odineyes AWS account ID
  external_id                    = "abcd-1234-efgh-5678"
  odineyes_api_url          = "https://api.odineyes.example.com"
  odineyes_api_key          = "your-api-key"
  odineyes_api_secret       = "your-api-secret"
  
  # Optional: Restrict to Odineyes scanner IP ranges
  odineyes_scanner_ip_cidrs = ["203.0.113.0/24"]
}

output "onboarding_status" {
  value = module.odineyes_onboarding.onboarding_status
}
