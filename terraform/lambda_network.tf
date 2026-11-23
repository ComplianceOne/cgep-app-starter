######################################################################
# GAP-05 — Put the intake Lambda inside the starter's VPC.
# HIPAA 164.312(e)(1) — Transmission security.
#
# The starter's private subnets have no NAT. Rather than add one, PHI
# traffic to DynamoDB and S3 stays on the AWS network via gateway
# endpoints, and the Lambda's security group can only reach those.
######################################################################

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Endpoint policies restrict what the VPC can reach to this workload's
# own table and bucket — no exfiltration path to other buckets/tables.
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "dynamodb:PutItem"
      Resource  = aws_dynamodb_table.intake.arn
    }]
  })

  tags = { Name = "${local.name_prefix}-ddb-endpoint" }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.uploads.arn}/*"
    }]
  })

  tags = { Name = "${local.name_prefix}-s3-endpoint" }
}

# No ingress. Egress is HTTPS only, and only to the two endpoints.
resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-${local.suffix}"
  description = "Intake Lambda: HTTPS egress to DynamoDB and S3 gateway endpoints only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-lambda-sg" }
}

resource "aws_vpc_security_group_egress_rule" "lambda_to_dynamodb" {
  security_group_id = aws_security_group.lambda.id
  description       = "HTTPS to DynamoDB gateway endpoint"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = aws_vpc_endpoint.dynamodb.prefix_list_id
}

resource "aws_vpc_security_group_egress_rule" "lambda_to_s3" {
  security_group_id = aws_security_group.lambda.id
  description       = "HTTPS to S3 gateway endpoint"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
}

# Lambda needs to create/delete ENIs in the VPC.
resource "aws_iam_role_policy_attachment" "lambda_vpc" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Take ownership of the VPC's default security group and strip its rules,
# so anything launched without an explicit group gets no network access.
resource "aws_default_security_group" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-default-sg-deny-all" }
}

######################################################################
# VPC flow logs — every accepted and rejected connection in the PHI
# network, to CloudWatch Logs under the audit CMK. HIPAA 164.312(b).
######################################################################

resource "aws_cloudwatch_log_group" "vpc_flow" {
  name              = local.vpc_log_group_name
  retention_in_days = 365
  kms_key_id        = aws_kms_key.audit.arn
}

data "aws_iam_policy_document" "vpc_flow_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_iam_role" "vpc_flow" {
  name               = "${local.name_prefix}-vpc-flow-${local.suffix}"
  assume_role_policy = data.aws_iam_policy_document.vpc_flow_trust.json
}

data "aws_iam_policy_document" "vpc_flow" {
  statement {
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"]
    resources = ["${aws_cloudwatch_log_group.vpc_flow.arn}:*"]
  }
}

resource "aws_iam_role_policy" "vpc_flow" {
  name   = "write-flow-log-group"
  role   = aws_iam_role.vpc_flow.id
  policy = data.aws_iam_policy_document.vpc_flow.json
}

resource "aws_flow_log" "main" {
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.vpc_flow.arn
  iam_role_arn             = aws_iam_role.vpc_flow.arn
  max_aggregation_interval = 60
}
