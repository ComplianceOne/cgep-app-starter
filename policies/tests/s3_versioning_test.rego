package hipaa.s3_versioning_test

import data.hipaa.s3_versioning
import rego.v1

bucket := {"address": "aws_s3_bucket.uploads", "mode": "managed", "type": "aws_s3_bucket", "expressions": {}}

versioning(status) := {
	"address": "aws_s3_bucket_versioning.uploads",
	"mode": "managed",
	"type": "aws_s3_bucket_versioning",
	"expressions": {
		"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]},
		"versioning_configuration": [{"status": {"constant_value": status}}],
	},
}

plan(resources) := {"configuration": {"root_module": {"resources": resources}}}

test_enabled_passes if {
	count(s3_versioning.deny) == 0 with input as plan([bucket, versioning("Enabled")])
}

test_missing_fails if {
	some msg in s3_versioning.deny with input as plan([bucket])
	contains(msg, "164.308(a)(7)")
	contains(msg, "aws_s3_bucket.uploads")
}

test_suspended_fails if {
	count(s3_versioning.deny) == 1 with input as plan([bucket, versioning("Suspended")])
}
