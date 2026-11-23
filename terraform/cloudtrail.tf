######################################################################
# CloudTrail — multi-region, log-file validation on, management events
# to a dedicated bucket. HIPAA 164.312(b) — Audit controls;
# 164.308(a)(1)(ii)(D) — Information system activity review.
######################################################################

resource "aws_s3_bucket" "cloudtrail" {
  #checkov:skip=CKV_AWS_18:This bucket holds the audit log itself; access to it is recorded as CloudTrail management events, and logging the log bucket into another bucket only moves the problem.
  #checkov:skip=CKV_AWS_144:Single-region sandbox; the trail is already multi-region and log file validation detects tampering. Replication belongs with the production log-archive account.
  bucket = "${local.name_prefix}-cloudtrail-${local.suffix}"
}

resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    id     = "abort-incomplete-multipart"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_notification" "cloudtrail" {
  bucket      = aws_s3_bucket.cloudtrail.id
  eventbridge = true
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "cloudtrail_bucket" {
  statement {
    sid       = "CloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "CloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.cloudtrail.arn, "${aws_s3_bucket.cloudtrail.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.cloudtrail]
}

######################################################################
# Trail -> CloudWatch Logs, so activity is searchable and retained
# alongside the API and VPC flow logs (365 days, audit CMK).
######################################################################

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = local.ct_log_group_name
  retention_in_days = 365
  kms_key_id        = aws_kms_key.audit.arn
}

data "aws_iam_policy_document" "cloudtrail_logs_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }
}

resource "aws_iam_role" "cloudtrail_logs" {
  name               = "${local.name_prefix}-cloudtrail-logs-${local.suffix}"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_logs_trust.json
}

data "aws_iam_policy_document" "cloudtrail_logs" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.cloudtrail.arn}:log-stream:*"]
  }
}

resource "aws_iam_role_policy" "cloudtrail_logs" {
  name   = "write-trail-log-group"
  role   = aws_iam_role.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_logs.json
}

resource "aws_cloudtrail" "main" {
  #checkov:skip=CKV_AWS_252:An SNS topic on the trail notifies on every log file delivered, which is noise. Alerting is event-specific instead: EventBridge rules in monitoring.tf.
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  kms_key_id                    = aws_kms_key.audit.arn
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_logs.arn

  # Management events everywhere, plus object-level (data) events on the
  # PHI uploads bucket and the evidence vault: who read, wrote or deleted
  # which object. HIPAA 164.312(b).
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.uploads.arn}/", "${aws_s3_bucket.evidence.arn}/"]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail, aws_iam_role_policy.cloudtrail_logs]
}
