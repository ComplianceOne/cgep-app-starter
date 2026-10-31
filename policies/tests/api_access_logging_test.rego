package hipaa.api_access_logging_test

import data.hipaa.api_access_logging
import rego.v1

stage(expressions) := {"configuration": {"root_module": {"resources": [{
	"address": "aws_apigatewayv2_stage.default",
	"mode": "managed",
	"type": "aws_apigatewayv2_stage",
	"expressions": expressions,
}]}}}

test_logging_passes if {
	count(api_access_logging.deny) == 0 with input as stage({"access_log_settings": [{
		"destination_arn": {"references": ["aws_cloudwatch_log_group.api_access.arn", "aws_cloudwatch_log_group.api_access"]},
	}]})
}

test_no_logging_fails if {
	some msg in api_access_logging.deny with input as stage({"auto_deploy": {"constant_value": true}})
	contains(msg, "164.312(b)")
	contains(msg, "aws_apigatewayv2_stage.default")
}
