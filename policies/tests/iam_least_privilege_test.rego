package hipaa.iam_least_privilege_test

import data.hipaa.iam_least_privilege
import rego.v1

role_policy := {
	"address": "aws_iam_role_policy.lambda_inline",
	"mode": "managed",
	"type": "aws_iam_role_policy",
	"expressions": {"policy": {"references": ["data.aws_iam_policy_document.lambda_inline.json", "data.aws_iam_policy_document.lambda_inline"]}},
}

doc(actions) := {
	"address": "data.aws_iam_policy_document.lambda_inline",
	"mode": "data",
	"type": "aws_iam_policy_document",
	"expressions": {"statement": [{
		"effect": {"constant_value": "Allow"},
		"actions": {"constant_value": actions},
	}]},
}

plan(resources) := {"configuration": {"root_module": {"resources": resources}}}

test_specific_actions_pass if {
	count(iam_least_privilege.deny) == 0 with input as plan([role_policy, doc(["dynamodb:PutItem", "s3:PutObject"])])
}

test_service_wildcard_fails if {
	some msg in iam_least_privilege.deny with input as plan([role_policy, doc(["dynamodb:*"])])
	contains(msg, "164.312(a)(1)")
	contains(msg, "dynamodb:*")
}

test_partial_wildcard_fails if {
	count(iam_least_privilege.deny) == 1 with input as plan([role_policy, doc(["s3:Get*"])])
}

# The starter's original GAP-07 shape on a fresh plan: jsonencode over
# unknown ARNs, so the actions are invisible. Must fail closed.
test_unverifiable_jsonencode_fails_closed if {
	opaque := json.patch(role_policy, [{"op": "replace", "path": "/expressions/policy", "value": {"references": ["aws_dynamodb_table.intake.arn"]}}])
	some msg in iam_least_privilege.deny with input as plan([opaque])
	contains(msg, "cannot be verified at plan time")
}

# The same policy on a plan with state: JSON is known, wildcard is visible.
test_known_json_wildcard_fails if {
	opaque := json.patch(role_policy, [{"op": "replace", "path": "/expressions/policy", "value": {}}])
	planned := {"root_module": {"resources": [{
		"address": "aws_iam_role_policy.lambda_inline",
		"values": {"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"s3:*\",\"Resource\":\"*\"}]}"},
	}]}}
	some msg in iam_least_privilege.deny with input as object.union(plan([opaque]), {"planned_values": planned})
	contains(msg, "s3:*")
}
