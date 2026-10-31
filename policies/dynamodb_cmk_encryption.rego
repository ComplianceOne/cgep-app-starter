# METADATA
# title: DynamoDB tables encrypted with a customer-managed KMS key
# description: >-
#   Every aws_dynamodb_table must enable server_side_encryption with a
#   kms_key_arn you own. Omitting the block uses an AWS-owned key; enabling
#   it without kms_key_arn uses the AWS-managed aws/dynamodb key.
# custom:
#   framework: HIPAA Security Rule
#   control_id: "164.312(a)(2)(iv)"
#   gap: GAP-02
#   severity: high
#   remediation: >-
#     Add server_side_encryption { enabled = true, kms_key_arn =
#     aws_kms_key.<yours>.arn } to the table.
package hipaa.dynamodb_cmk_encryption

import data.hipaa.lib
import rego.v1

deny contains msg if {
	some t in lib.resources_of("aws_dynamodb_table")
	not cmk_encrypted(t)
	msg := sprintf(
		"[HIPAA 164.312(a)(2)(iv)] GAP-02 %s is not encrypted with a customer-managed KMS key. Remediation: add server_side_encryption { enabled = true, kms_key_arn = aws_kms_key.<yours>.arn }.",
		[t.address],
	)
}

cmk_encrypted(t) if {
	some s in t.expressions.server_side_encryption
	lib.const(s.enabled) == true
	lib.customer_key(s.kms_key_arn)
}
