# METADATA
# title: S3 buckets have versioning enabled
# description: >-
#   Every aws_s3_bucket must have versioning Enabled so overwritten or
#   deleted PHI can be recovered.
# custom:
#   framework: HIPAA Security Rule
#   control_id: "164.308(a)(7)"
#   gap: GAP-04
#   severity: medium
#   remediation: >-
#     Add aws_s3_bucket_versioning referencing the bucket with
#     versioning_configuration { status = "Enabled" }.
package hipaa.s3_versioning

import data.hipaa.lib
import rego.v1

deny contains msg if {
	some b in lib.resources_of("aws_s3_bucket")
	not versioned(b.address)
	msg := sprintf(
		"[HIPAA 164.308(a)(7)] GAP-04 %s does not have versioning enabled; overwritten PHI is unrecoverable. Remediation: add aws_s3_bucket_versioning for this bucket with versioning_configuration { status = \"Enabled\" }.",
		[b.address],
	)
}

versioned(addr) if {
	some v in lib.resources_of("aws_s3_bucket_versioning")
	lib.references(v.expressions.bucket, addr)
	some cfg in v.expressions.versioning_configuration
	lib.const(cfg.status) == "Enabled"
}
