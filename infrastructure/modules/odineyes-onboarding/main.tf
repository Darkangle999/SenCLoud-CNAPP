resource "aws_iam_role" "odineyes_readonly" {
  name               = var.role_name
  assume_role_policy = jsonencode(
    {
      Version = "2012-10-17"
      Statement = [
        {
          Action = "sts:AssumeRole"
          Condition = merge(
            {
              StringEquals = {
                "sts:ExternalId" = var.external_id
              }
            },
            length(var.odineyes_scanner_ip_cidrs) > 0 ? {
              IpAddress = {
                "aws:SourceIp" = var.odineyes_scanner_ip_cidrs
              }
            } : {}
          )
          Effect = "Allow"
          Principal = {
            AWS = "arn:aws:iam::${var.odineyes_account_id}:root"
          }
        },
      ]
    }
  )
}

resource "aws_iam_role_policy_attachment" "odineyes_security_audit" {
  count      = var.policy_mode == "managed" ? 1 : 0
  role       = aws_iam_role.odineyes_readonly.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "odineyes_view_only" {
  count      = var.policy_mode == "managed" ? 1 : 0
  role       = aws_iam_role.odineyes_readonly.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_iam_role_policy" "odineyes_least_privilege" {
  count  = var.policy_mode == "least-privilege" ? 1 : 0
  name   = "OdineyesLeastPrivilege"
  role   = aws_iam_role.odineyes_readonly.id
  policy = var.least_privilege_policy_json
}
