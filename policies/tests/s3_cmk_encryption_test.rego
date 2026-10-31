package hipaa.s3_cmk_encryption_test

import data.hipaa.s3_cmk_encryption
import rego.v1

bucket := {"address": "aws_s3_bucket.uploads", "mode": "managed", "type": "aws_s3_bucket", "expressions": {}}

sse(algorithm, key_expr) := {
	"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
	"mode": "managed",
	"type": "aws_s3_bucket_server_side_encryption_configuration",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
		"rule": [{"apply_server_side_encryption_by_default": [{
			"sse_algorithm": {"constant_value": algorithm},
			"kms_master_key_id": key_expr,
		}]}],
	},
}

plan(resources) := {"configuration": {"root_module": {"resources": resources}}}

cmk := {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]}

test_cmk_passes if {
	count(s3_cmk_encryption.deny) == 0 with input as plan([bucket, sse("aws:kms", cmk)])
}

test_no_sse_config_fails if {
	some msg in s3_cmk_encryption.deny with input as plan([bucket])
	contains(msg, "164.312(a)(2)(iv)")
	contains(msg, "aws_s3_bucket.uploads")
}

test_sse_s3_fails if {
	count(s3_cmk_encryption.deny) == 1 with input as plan([bucket, sse("AES256", {})])
}

test_aws_managed_alias_fails if {
	count(s3_cmk_encryption.deny) == 1 with input as plan([bucket, sse("aws:kms", {"constant_value": "alias/aws/s3"})])
}
