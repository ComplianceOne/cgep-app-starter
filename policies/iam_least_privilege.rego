# METADATA
# title: IAM policies grant no wildcard actions
# description: >-
#   Inline role policies and customer-managed policies must not Allow
#   wildcard actions (e.g. "*", "s3:*", "dynamodb:Get*"). The policy must be
#   verifiable at plan time; an opaque policy fails closed.
# custom:
#   framework: HIPAA Security Rule
#   control_id: "164.312(a)(1)"
#   gap: GAP-07
#   severity: high
#   remediation: >-
#     Replace wildcard actions with the specific API calls the workload makes,
#     and author the policy with data.aws_iam_policy_document.
package hipaa.iam_least_privilege

import data.hipaa.lib
import rego.v1

policy_types := {"aws_iam_role_policy", "aws_iam_policy"}

iam_policies := [p |
	some t in policy_types
	some p in lib.resources_of(t)
]

deny contains msg if {
	some p in iam_policies
	some s in lib.statements(p)
	s.effect == "Allow"
	some action in s.actions
	contains(action, "*")
	msg := sprintf(
		"[HIPAA 164.312(a)(1)] GAP-07 %s allows wildcard action %q. Remediation: grant only the specific actions the workload calls (e.g. dynamodb:PutItem, s3:PutObject).",
		[p.address, action],
	)
}

deny contains msg if {
	some p in iam_policies
	not lib.verifiable(p)
	msg := sprintf(
		"[HIPAA 164.312(a)(1)] GAP-07 %s cannot be verified at plan time (jsonencode over values known only after apply). Remediation: author it with data.aws_iam_policy_document so its actions are reviewable before apply.",
		[p.address],
	)
}
