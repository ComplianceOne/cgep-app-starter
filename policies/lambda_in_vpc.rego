# METADATA
# title: Lambda functions run inside a VPC
# description: >-
#   Every aws_lambda_function that handles PHI must set vpc_config with
#   subnets and security groups, so its network path is governed rather than
#   the default Lambda-managed network.
# custom:
#   framework: HIPAA Security Rule
#   control_id: "164.312(e)(1)"
#   gap: GAP-05
#   severity: high
#   remediation: >-
#     Add vpc_config { subnet_ids = aws_subnet.private[*].id,
#     security_group_ids = [aws_security_group.<yours>.id] } to the function.
package hipaa.lambda_in_vpc

import data.hipaa.lib
import rego.v1

deny contains msg if {
	some f in lib.resources_of("aws_lambda_function")
	not in_vpc(f)
	msg := sprintf(
		"[HIPAA 164.312(e)(1)] GAP-05 %s is not attached to a VPC. Remediation: add vpc_config with subnet_ids (private subnets) and security_group_ids.",
		[f.address],
	)
}

in_vpc(f) if {
	some v in f.expressions.vpc_config
	lib.is_set(v.subnet_ids)
	lib.is_set(v.security_group_ids)
}
