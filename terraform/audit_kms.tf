######################################################################
# Customer-managed KMS key for audit data: the evidence vault,
# CloudTrail logs and API access logs.
#
# Kept separate from the PHI key (kms.tf) so the people and services
# that can decrypt PHI are not the same ones that can decrypt the audit
# record of what happened to it. HIPAA 164.312(b) — Audit controls.
######################################################################

data "aws_caller_identity" "current" {}

locals {
  account_id         = data.aws_caller_identity.current.account_id
  trail_name         = "${local.name_prefix}-trail-${local.suffix}"
  trail_arn          = "arn:aws:cloudtrail:${var.aws_region}:${local.account_id}:trail/${local.trail_name}"
  api_log_group_name = "/aws/apigateway/${local.name_prefix}-api-${local.suffix}/access"
}

resource "aws_kms_key" "audit" {
  description             = "Acme Health CMK for audit data (evidence vault, CloudTrail, API access logs)"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid       = "AccountAdministersKeyViaIAM"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudTrailEncryptsThisTrailOnly"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:GenerateDataKey*"
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = local.trail_arn }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:aws:cloudtrail:*:${local.account_id}:trail/*" }
        }
      },
      {
        Sid       = "CloudTrailDescribesKey"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "kms:DescribeKey"
        Resource  = "*"
      },
      {
        Sid       = "CloudWatchLogsEncryptsApiAccessLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.${var.aws_region}.amazonaws.com" }
        Action    = ["kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"]
        Resource  = "*"
        Condition = {
          ArnEquals = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:${local.api_log_group_name}"
          }
        }
      }
      ],
      # Grader read access (see evidence_vault.tf): decrypt via S3 only, and
      # only for objects in the evidence vault.
      length(var.evidence_readers) == 0 ? [] : [{
        Sid       = "EvidenceReadersDecryptViaS3"
        Effect    = "Allow"
        Principal = { AWS = var.evidence_readers }
        Action    = ["kms:Decrypt", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          StringEquals = { "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com" }
          StringLike   = { "kms:EncryptionContext:aws:s3:arn" = "arn:aws:s3:::${local.name_prefix}-evidence-${local.suffix}*" }
        }
    }])
  })
}

resource "aws_kms_alias" "audit" {
  name          = "alias/${local.name_prefix}-audit-${local.suffix}"
  target_key_id = aws_kms_key.audit.key_id
}
