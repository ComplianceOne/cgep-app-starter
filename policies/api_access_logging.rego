# METADATA
# title: API Gateway stages write access logs
# description: >-
#   Every API Gateway stage (HTTP or REST) in front of PHI must send access
#   logs to a destination, so requests can be recorded and examined.
# custom:
#   framework: HIPAA Security Rule
#   control_id: "164.312(b)"
#   gap: GAP-08
#   severity: medium
#   remediation: >-
#     Add access_log_settings { destination_arn =
#     aws_cloudwatch_log_group.<yours>.arn, format = ... } to the stage.
package hipaa.api_access_logging

import data.hipaa.lib
import rego.v1

stage_types := {"aws_apigatewayv2_stage", "aws_api_gateway_stage"}

deny contains msg if {
	some t in stage_types
	some s in lib.resources_of(t)
	not access_logged(s)
	msg := sprintf(
		"[HIPAA 164.312(b)] GAP-08 %s has no access logging. Remediation: add access_log_settings with destination_arn pointing at a CloudWatch log group.",
		[s.address],
	)
}

access_logged(s) if {
	some a in s.expressions.access_log_settings
	lib.is_set(a.destination_arn)
}
