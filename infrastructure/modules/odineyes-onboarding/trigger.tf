data "external" "odineyes_autoconnect" {
  program = ["python3", "${path.module}/trigger.py"]

  query = {
    api_url     = var.odineyes_api_url
    api_key     = sensitive(var.odineyes_api_key)
    api_secret  = sensitive(var.odineyes_api_secret)
    external_id = var.external_id
    role_arn    = aws_iam_role.odineyes_readonly.arn
    cloud       = "aws"
  }
}
