package hipaa.lambda_in_vpc_test

import data.hipaa.lambda_in_vpc
import rego.v1

fn(expressions) := {"configuration": {"root_module": {"resources": [{
	"address": "aws_lambda_function.intake",
	"mode": "managed",
	"type": "aws_lambda_function",
	"expressions": expressions,
}]}}}

test_in_vpc_passes if {
	count(lambda_in_vpc.deny) == 0 with input as fn({"vpc_config": [{
		"subnet_ids": {"references": ["aws_subnet.private"]},
		"security_group_ids": {"references": ["aws_security_group.lambda.id", "aws_security_group.lambda"]},
	}]})
}

test_no_vpc_config_fails if {
	some msg in lambda_in_vpc.deny with input as fn({})
	contains(msg, "164.312(e)(1)")
	contains(msg, "aws_lambda_function.intake")
}

test_empty_subnets_fails if {
	count(lambda_in_vpc.deny) == 1 with input as fn({"vpc_config": [{
		"subnet_ids": {"constant_value": []},
		"security_group_ids": {"references": ["aws_security_group.lambda"]},
	}]})
}
