package hipaa.dynamodb_cmk_encryption_test

import data.hipaa.dynamodb_cmk_encryption
import rego.v1

table(expressions) := {"configuration": {"root_module": {"resources": [{
	"address": "aws_dynamodb_table.intake",
	"mode": "managed",
	"type": "aws_dynamodb_table",
	"expressions": expressions,
}]}}}

test_cmk_passes if {
	count(dynamodb_cmk_encryption.deny) == 0 with input as table({"server_side_encryption": [{
		"enabled": {"constant_value": true},
		"kms_key_arn": {"references": ["aws_kms_key.phi.arn", "aws_kms_key.phi"]},
	}]})
}

test_aws_owned_default_fails if {
	some msg in dynamodb_cmk_encryption.deny with input as table({})
	contains(msg, "164.312(a)(2)(iv)")
	contains(msg, "aws_dynamodb_table.intake")
}

test_aws_managed_key_fails if {
	count(dynamodb_cmk_encryption.deny) == 1 with input as table({"server_side_encryption": [{"enabled": {"constant_value": true}}]})
}
