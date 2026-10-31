######################################################################
# Bootstrap — what the pipeline needs before it can run.
#
# Applied once, by hand, with local state (the pipeline cannot mint its
# own credentials). Creates:
#   - S3 bucket for the workload's Terraform state (native S3 locking)
#   - KMS key for that state
#   - Two GitHub OIDC roles with separated duties:
#       grc-pipeline-plan   pull requests only, read-only
#       grc-pipeline-apply  main branch only, can change infrastructure
#
# Role names deliberately do NOT use the workload's "acme-health-intake-"
# prefix, so the apply role (which may manage IAM under that prefix)
# cannot modify its own permissions.
######################################################################

terraform {
  required_version = ">= 1.10"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = "acme-health-intake"
      ManagedBy = "terraform-bootstrap"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

# The repo uses GitHub's immutable subject claims: owner and repo are
# pinned by numeric ID, so a renamed or re-created repo with the same
# name cannot inherit these roles. Read it with:
#   gh api repos/<owner>/<repo>/actions/oidc/customization/sub
variable "github_sub_prefix" {
  type        = string
  description = "OIDC sub claim prefix of the repo allowed to assume the pipeline roles."
  default     = "repo:ComplianceOne@193837465/cgep-app-starter@1441223577"
}

data "aws_caller_identity" "current" {}

# Created in Lab 4.3; one per account, so reference it rather than own it.
data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  workload   = "acme-health-intake"

  # PHI stores. Pipeline roles manage these resources but never read
  # their contents.
  phi_data_arns = [
    "arn:aws:s3:::${local.workload}-uploads-*/*",
    "arn:aws:dynamodb:*:${local.account_id}:table/${local.workload}-*",
  ]
  evidence_objects_arn = "arn:aws:s3:::${local.workload}-evidence-*/*"
}

######################################################################
# Terraform state bucket
######################################################################

resource "aws_kms_key" "state" {
  description             = "Acme Health CMK for Terraform state"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "state" {
  name          = "alias/${local.workload}-tfstate"
  target_key_id = aws_kms_key.state.key_id
}

resource "aws_s3_bucket" "state" {
  bucket = "${local.workload}-tfstate-${random_id.suffix.hex}"
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "state_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]

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

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.state]
}

######################################################################
# Guardrails shared by both pipeline roles
######################################################################

data "aws_iam_policy_document" "guardrails" {
  statement {
    sid       = "NeverReadPHI"
    effect    = "Deny"
    actions   = ["s3:GetObject", "s3:GetObjectVersion", "dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:ExportTableToPointInTime"]
    resources = local.phi_data_arns
  }

  statement {
    sid       = "NeverWeakenEvidenceLock"
    effect    = "Deny"
    actions   = ["s3:BypassGovernanceRetention", "s3:PutObjectRetention", "s3:PutObjectLegalHold", "s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = [local.evidence_objects_arn]
  }
}

######################################################################
# Plan role — pull requests, read-only
######################################################################

data "aws_iam_policy_document" "plan_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["${var.github_sub_prefix}:pull_request"]
    }
  }
}

resource "aws_iam_role" "plan" {
  name                 = "grc-pipeline-plan"
  description          = "GitHub Actions, pull requests: terraform plan + policy check. Read-only."
  assume_role_policy   = data.aws_iam_policy_document.plan_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "plan_readonly" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "plan_state" {
  statement {
    sid       = "ReadState"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
  }

  statement {
    sid       = "DecryptState"
    effect    = "Allow"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.state.arn]
  }
}

resource "aws_iam_role_policy" "plan_state" {
  name   = "terraform-state-read"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.plan_state.json
}

resource "aws_iam_role_policy" "plan_guardrails" {
  name   = "guardrails"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.guardrails.json
}

######################################################################
# Apply role — main branch only
######################################################################

data "aws_iam_policy_document" "apply_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["${var.github_sub_prefix}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "apply" {
  name                 = "grc-pipeline-apply"
  description          = "GitHub Actions, main branch: terraform apply, sign + upload evidence."
  assume_role_policy   = data.aws_iam_policy_document.apply_trust.json
  max_session_duration = 3600
}

# PowerUserAccess covers every service the workload uses except IAM.
resource "aws_iam_role_policy_attachment" "apply_poweruser" {
  role       = aws_iam_role.apply.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

# IAM only under the workload prefix, so the role cannot touch itself.
data "aws_iam_policy_document" "apply_iam" {
  statement {
    sid    = "ManageWorkloadRoles"
    effect = "Allow"
    actions = [
      "iam:CreateRole", "iam:DeleteRole", "iam:GetRole", "iam:UpdateRole", "iam:UpdateAssumeRolePolicy",
      "iam:TagRole", "iam:UntagRole", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole", "iam:PutRolePolicy", "iam:GetRolePolicy", "iam:DeleteRolePolicy",
      "iam:AttachRolePolicy", "iam:DetachRolePolicy",
    ]
    resources = ["arn:aws:iam::${local.account_id}:role/${local.workload}-*"]
  }

  statement {
    sid       = "PassWorkloadRoleToLambdaOnly"
    effect    = "Allow"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::${local.account_id}:role/${local.workload}-*"]

    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }

  statement {
    sid       = "ReadOIDCProvider"
    effect    = "Allow"
    actions   = ["iam:GetOpenIDConnectProvider", "iam:ListOpenIDConnectProviders"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "apply_iam" {
  name   = "workload-iam"
  role   = aws_iam_role.apply.id
  policy = data.aws_iam_policy_document.apply_iam.json
}

resource "aws_iam_role_policy" "apply_guardrails" {
  name   = "guardrails"
  role   = aws_iam_role.apply.id
  policy = data.aws_iam_policy_document.guardrails.json
}

######################################################################
# Outputs — feed backend.tf and the GitHub repo variables.
######################################################################

output "state_bucket" {
  value = aws_s3_bucket.state.id
}

output "state_kms_key_arn" {
  value = aws_kms_key.state.arn
}

output "plan_role_arn" {
  value = aws_iam_role.plan.arn
}

output "apply_role_arn" {
  value = aws_iam_role.apply.arn
}
