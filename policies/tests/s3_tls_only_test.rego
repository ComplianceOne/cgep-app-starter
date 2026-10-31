package hipaa.s3_tls_only_test

import data.hipaa.s3_tls_only
import rego.v1

bucket := {"address": "aws_s3_bucket.uploads", "mode": "managed", "type": "aws_s3_bucket", "expressions": {}}

bucket_policy := {
	"address": "aws_s3_bucket_policy.uploads",
	"mode": "managed",
	"type": "aws_s3_bucket_policy",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
		"policy": {"references": ["data.aws_iam_policy_document.tls.json", "data.aws_iam_policy_document.tls"]},
	},
}

doc(effect, condition_value) := {
	"address": "data.aws_iam_policy_document.tls",
	"mode": "data",
	"type": "aws_iam_policy_document",
	"expressions": {"statement": [{
		"effect": {"constant_value": effect},
		"actions": {"constant_value": ["s3:*"]},
		"condition": [{
			"test": {"constant_value": "Bool"},
			"variable": {"constant_value": "aws:SecureTransport"},
			"values": {"constant_value": [condition_value]},
		}],
	}]},
}

plan(resources) := {"configuration": {"root_module": {"resources": resources}}}

test_policy_document_deny_passes if {
	count(s3_tls_only.deny) == 0 with input as plan([bucket, bucket_policy, doc("Deny", "false")])
}

test_known_json_deny_passes if {
	jsonpolicy := {
		"address": "aws_s3_bucket_policy.uploads",
		"mode": "managed",
		"type": "aws_s3_bucket_policy",
		"expressions": {
			"bucket": {"references": ["aws_s3_bucket.uploads"]},
			"policy": {},
		},
	}
	planned := {"root_module": {"resources": [{
		"address": "aws_s3_bucket_policy.uploads",
		"values": {"policy": "{\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"s3:*\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"},
	}]}}
	count(s3_tls_only.deny) == 0 with input as object.union(plan([bucket, jsonpolicy]), {"planned_values": planned})
}

test_no_bucket_policy_fails if {
	some msg in s3_tls_only.deny with input as plan([bucket])
	contains(msg, "164.312(e)(1)")
	contains(msg, "aws_s3_bucket.uploads")
}

test_allow_instead_of_deny_fails if {
	count(s3_tls_only.deny) == 1 with input as plan([bucket, bucket_policy, doc("Allow", "false")])
}

test_opaque_policy_fails_closed if {
	opaque := json.patch(bucket_policy, [{"op": "replace", "path": "/expressions/policy", "value": {"references": ["aws_s3_bucket.uploads.arn"]}}])
	count(s3_tls_only.deny) == 1 with input as plan([bucket, opaque])
}
