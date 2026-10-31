# METADATA
# title: S3 buckets encrypted with a customer-managed KMS key
# description: >-
#   Every aws_s3_bucket must have an SSE configuration using aws:kms with a
#   customer-managed key. SSE-S3 (AES256) or the aws/s3 managed alias leaves
#   PHI key custody with AWS.
# custom:
#   framework: HIPAA Security Rule
#   control_id: "164.312(a)(2)(iv)"
#   gap: GAP-01
#   severity: high
#   remediation: >-
#     Add aws_s3_bucket_server_side_encryption_configuration referencing the
#     bucket, with sse_algorithm = "aws:kms" and kms_master_key_id set to an
#     aws_kms_key you own.
package hipaa.s3_cmk_encryption

import data.hipaa.lib
import rego.v1

deny contains msg if {
	some b in lib.resources_of("aws_s3_bucket")
	not cmk_encrypted(b.address)
	msg := sprintf(
		"[HIPAA 164.312(a)(2)(iv)] GAP-01 %s is not encrypted with a customer-managed KMS key. Remediation: add aws_s3_bucket_server_side_encryption_configuration for this bucket with sse_algorithm = \"aws:kms\" and kms_master_key_id = aws_kms_key.<yours>.arn.",
		[b.address],
	)
}

cmk_encrypted(addr) if {
	some e in lib.resources_of("aws_s3_bucket_server_side_encryption_configuration")
	lib.references(e.expressions.bucket, addr)
	some rule in e.expressions.rule
	some d in rule.apply_server_side_encryption_by_default
	lib.const(d.sse_algorithm) in {"aws:kms", "aws:kms:dsse"}
	lib.customer_key(d.kms_master_key_id)
}
