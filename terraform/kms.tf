######################################################################
# Customer-managed KMS key for PHI at rest.
# HIPAA 164.312(a)(2)(iv) — Encryption and decryption.
# Closes custody half of GAP-01 (S3) and GAP-02 (DynamoDB).
######################################################################

resource "aws_kms_key" "phi" {
  description             = "Acme Health CMK for PHI at rest (intake uploads + submissions)"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi-${local.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}

# The Lambda writes PHI into the CMK-encrypted bucket and table, so it
# needs to use the key. Scoped to this key only.
data "aws_iam_policy_document" "lambda_kms" {
  statement {
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.phi.arn]
  }
}

resource "aws_iam_role_policy" "lambda_kms" {
  name   = "${local.name_prefix}-lambda-kms-${local.suffix}"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda_kms.json
}
