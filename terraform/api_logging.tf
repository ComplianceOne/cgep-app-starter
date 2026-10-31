######################################################################
# GAP-08 — API Gateway access logs, encrypted with the audit CMK.
# HIPAA 164.312(b) — Audit controls. Throttling is set on the stage in
# main.tf. WAF is not supported on API Gateway HTTP APIs; see WRITEUP.
######################################################################

resource "aws_cloudwatch_log_group" "api_access" {
  name              = local.api_log_group_name
  retention_in_days = 365
  kms_key_id        = aws_kms_key.audit.arn
}
