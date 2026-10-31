######################################################################
# Remote state, created by bootstrap/. Encrypted with its own CMK,
# versioned, TLS-only, and locked natively in S3 (no DynamoDB table).
######################################################################

terraform {
  backend "s3" {
    bucket       = "acme-health-intake-tfstate-a1fc19eb"
    key          = "workload/terraform.tfstate"
    region       = "us-east-1"
    encrypt      = true
    kms_key_id   = "arn:aws:kms:us-east-1:697020387897:key/1577380c-c9e7-432d-8c04-a0ad1584cf80"
    use_lockfile = true
  }
}
