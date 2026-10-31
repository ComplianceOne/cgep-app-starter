# METADATA
# title: Terraform plan helpers
# description: >-
#   Shared helpers for reading `terraform show -json` output. Policies read
#   the `configuration` section (references + constants), which is fully
#   populated even on a fresh plan where most planned values are unknown.
#   Root module only: the capstone workload has no child modules.
package hipaa.lib

import rego.v1

config_resources := object.get(input, ["configuration", "root_module", "resources"], [])

planned_resources := object.get(input, ["planned_values", "root_module", "resources"], [])

# All managed resources of a type, as configuration entries.
resources_of(type) := [r |
	some r in config_resources
	r.mode == "managed"
	r.type == type
]

# The constant value of an expression, if it is a literal.
const(expr) := expr.constant_value

# True when an expression references the given resource address.
references(expr, addr) if {
	some ref in object.get(expr, "references", [])
	ref == addr
}

# True when an attribute is set to something: a reference or a non-empty literal.
is_set(expr) if count(object.get(expr, "references", [])) > 0

is_set(expr) if {
	v := expr.constant_value
	not v in {null, "", []}
}

# A KMS key the customer controls: set, and not an AWS-managed alias.
customer_key(expr) if {
	is_set(expr)
	not aws_managed_alias(expr)
}

aws_managed_alias(expr) if startswith(expr.constant_value, "alias/aws/")

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)

######################################################################
# IAM-style policy statements, normalised to
#   {"effect": "...", "actions": [...], "conditions": [{test, variable, values}]}
# from either source the gate can verify at plan time:
#   1. a data.aws_iam_policy_document the policy attribute references
#   2. a planned `policy` JSON string that is already known
# A policy that is neither (jsonencode over unknown ARNs on a fresh
# plan) is unverifiable, and policies treat that as a failure.
######################################################################

policy_documents(r) := [d |
	some ref in object.get(r.expressions.policy, "references", [])
	some d in config_resources
	d.mode == "data"
	d.type == "aws_iam_policy_document"
	d.address == ref
]

doc_statements(r) := {s |
	some d in policy_documents(r)
	some st in object.get(d.expressions, "statement", [])
	s := {
		"effect": object.get(st, ["effect", "constant_value"], "Allow"),
		"actions": object.get(st, ["actions", "constant_value"], []),
		"conditions": [c |
			some cb in object.get(st, "condition", [])
			c := {
				"test": object.get(cb, ["test", "constant_value"], ""),
				"variable": object.get(cb, ["variable", "constant_value"], ""),
				"values": object.get(cb, ["values", "constant_value"], []),
			}
		],
	}
}

planned_policy(addr) := p if {
	some pr in planned_resources
	pr.address == addr
	p := pr.values.policy
	is_string(p)
}

json_statements(r) := {s |
	doc := json.unmarshal(planned_policy(r.address))
	some st in as_array(doc.Statement)
	s := {
		"effect": st.Effect,
		"actions": as_array(object.get(st, "Action", [])),
		"conditions": [c |
			some test, kvs in object.get(st, "Condition", {})
			some variable, vals in kvs
			c := {"test": test, "variable": variable, "values": as_array(vals)}
		],
	}
}

statements(r) := doc_statements(r) | json_statements(r)

verifiable(r) if count(policy_documents(r)) > 0

verifiable(r) if planned_policy(r.address)
