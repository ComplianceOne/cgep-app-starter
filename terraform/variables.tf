variable "aws_region" {
  type        = string
  description = "AWS region for the starter."
  default     = "us-east-1"
}

# External verifiers (e.g. the capstone grader) granted read-only access to
# the evidence vault. Changing this list goes through the policy gate and
# produces its own signed evidence bundle.
variable "evidence_readers" {
  type        = list(string)
  description = "IAM principal ARNs allowed to read and verify evidence bundles."
  default     = []
}
