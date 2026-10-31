# METADATA
# title: S3 buckets deny non-TLS requests
# description: >-
#   Every aws_s3_bucket must have a bucket policy with a Deny statement
#   conditioned on aws:SecureTransport = false. The policy must be
#   verifiable at plan time (an aws_iam_policy_document, or already-known
#   JSON); an opaque policy fails closed.
# custom:
#   framework: HIPAA Security Rule
#   control_id: "164.312(e)(1)"
#   gap: GAP-03
#   severity: high
#   remediation: >-
#     Attach aws_s3_bucket_policy built from data.aws_iam_policy_document with
#     a Deny on s3:* where condition Bool aws:SecureTransport = "false".
package hipaa.s3_tls_only

import data.hipaa.lib
import rego.v1

deny contains msg if {
	some b in lib.resources_of("aws_s3_bucket")
	not tls_enforced(b.address)
	msg := sprintf(
		"[HIPAA 164.312(e)(1)] GAP-03 %s has no verifiable bucket policy denying requests where aws:SecureTransport is false. Remediation: attach aws_s3_bucket_policy from a data.aws_iam_policy_document with Deny s3:* on condition Bool aws:SecureTransport = \"false\".",
		[b.address],
	)
}

tls_enforced(addr) if {
	some p in lib.resources_of("aws_s3_bucket_policy")
	lib.references(p.expressions.bucket, addr)
	some s in lib.statements(p)
	s.effect == "Deny"
	some c in s.conditions
	c.test == "Bool"
	c.variable == "aws:SecureTransport"
	some v in lib.as_array(c.values)
	lower(sprintf("%v", [v])) == "false"
}
