######################################################################
# Continuous monitoring and detection.
#
# EventBridge rules match CloudTrail events that would weaken a HIPAA
# control and route them to an encrypted SNS topic. Changes made by the
# gated pipeline (grc-pipeline-apply) are expected and excluded from the
# configuration-change rules; anything else is out-of-band and alerts.
# Tampering with the trail or the evidence vault alerts regardless of who
# does it.
#
# Patterns live in detections/*.json; tests/detections/ checks each one
# against real EventBridge matching (aws events test-event-pattern).
# HIPAA 164.308(a)(1)(ii)(D) information system activity review, plus the
# control each rule protects (tag hipaa_control).
######################################################################

locals {
  detections = {
    "audit-trail-tampering" = {
      control     = "164.312(b)"
      description = "CloudTrail stopped, deleted or reconfigured (any principal)."
    }
    "kms-key-tampering" = {
      control     = "164.312(a)(2)(iv)"
      description = "KMS key disabled, scheduled for deletion, rotation disabled or policy changed outside the pipeline."
    }
    "bucket-protection-change" = {
      control     = "164.312(e)(1)"
      description = "Policy, encryption, versioning, public access block, ACL or Object Lock changed on a workload bucket outside the pipeline."
    }
    "workload-iam-change" = {
      control     = "164.312(a)(1)"
      description = "Permissions or trust changed on a workload or pipeline role outside the pipeline."
    }
    "evidence-deletion-attempt" = {
      control     = "164.312(c)(1)"
      description = "Delete, retention or legal-hold call against the evidence vault (any principal)."
    }
    "root-account-activity" = {
      control     = "164.308(a)(1)(ii)(D)"
      description = "Any API call or console sign-in by the account root user."
    }
  }
}

variable "alert_email" {
  type        = string
  description = "Address subscribed to security alerts. Empty = topic only (subscribe out of band)."
  default     = ""
}

resource "aws_sns_topic" "security_alerts" {
  name              = "${local.name_prefix}-security-alerts-${local.suffix}"
  kms_master_key_id = aws_kms_key.audit.arn
}

data "aws_iam_policy_document" "security_alerts" {
  statement {
    sid       = "EventBridgeRulesPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.security_alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:events:${var.aws_region}:${local.account_id}:rule/${local.name_prefix}-*"]
    }
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.security_alerts.json
}

resource "aws_sns_topic_subscription" "security_alerts_email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "detection" {
  for_each      = local.detections
  name          = "${local.name_prefix}-${each.key}"
  description   = "[HIPAA ${each.value.control}] ${each.value.description}"
  event_pattern = file("${path.module}/detections/${each.key}.json")

  # AWS tag values cannot contain parentheses, so tag with the OSCAL
  # control ID form: 164.312(a)(2)(iv) -> hipaa-164.312-a-2-iv.
  tags = { hipaa_control = "hipaa-${trim(replace(lower(each.value.control), "/[()]+/", "-"), "-")}" }
}

resource "aws_cloudwatch_event_target" "detection" {
  for_each = local.detections
  rule     = aws_cloudwatch_event_rule.detection[each.key].name
  arn      = aws_sns_topic.security_alerts.arn

  # Lead with what fired and why it matters, then the raw event.
  input_transformer {
    input_paths = {
      event  = "$.detail.eventName"
      who    = "$.detail.userIdentity.arn"
      source = "$.detail.sourceIPAddress"
      when   = "$.time"
    }
    input_template = "\"[HIPAA ${each.value.control}] ${each.key}: <event> by <who> from <source> at <when>. ${each.value.description}\""
  }
}
