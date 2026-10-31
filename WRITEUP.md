# Acme Health Patient Intake API: making it audit-defensible

My primary framework is the **HIPAA Security Rule (45 CFR 164 Subpart C)**. Acme is a telehealth provider, so it is a HIPAA covered entity, and the intake API stores patient-submitted ePHI. HIPAA is the obligation Acme already has, while SOC 2 and CMMC are commitments it is choosing to pursue. Every policy, Terraform override and OSCAL statement in this repo cites a HIPAA section. Where a SOC 2 or CMMC control would also be met, I don't claim it.

The system is the unchanged starter workload (API Gateway, Lambda, DynamoDB, S3, VPC) with four layers around it:

| Layer | Where | What it does |
|---|---|---|
| 1. Terraform baseline | `terraform/`, `bootstrap/` | Customer-managed KMS keys, Object Lock evidence vault, CloudTrail, and overrides that close seven of the eight gaps |
| 2. Policy suite | `policies/` | Seven Rego policies, one per gap, each citing a HIPAA section; 25 unit tests |
| 3. Pipeline | `.github/workflows/grc-gate.yml` | Plan, Policy check, Apply, Sign, Upload. Pull requests are read-only; `main` applies and files signed evidence |
| 4. OSCAL | `oscal/` | Catalog, profile and component definition describing what was built, validated with trestle on every run |

## Design decisions

**Close gaps in Terraform and enforce them in policy.** Each gap I address is fixed twice. The Terraform override fixes it today, and the Rego policy stops it coming back. A fix with no gate decays the first time someone refactors. A gate with no fix just blocks every PR. During development I re-introduced each closed gap into the hardened config, one at a time, against real state, and confirmed the gate blocked on exactly the matching policy and no other. PR #4 (`dynamodb:*` re-introduced) shows the same thing in the repo history: red, and blocked from merging.

**Policies read the plan's configuration, and fail closed when they can't see.** On a fresh plan, an IAM or bucket policy built with `jsonencode()` over ARNs that don't exist yet is a single unknown value. Conftest sees `null`, so the starter's original `dynamodb:*` is invisible. I rewrote every IAM and bucket policy as `aws_iam_policy_document`, whose actions and conditions stay visible as constants in the plan. That change produced no diff in AWS. The policies then treat any policy they cannot read as a violation. That's what lets the gate catch a reverted GAP-07 in an empty account as well as in mine.

**Two KMS keys, split by who needs them.** The PHI key encrypts the uploads bucket and submissions table, and only the Lambda can use it. A separate audit key encrypts the evidence vault, CloudTrail logs and API access logs. The people and services that can read PHI should not be the same ones that can read, or quietly alter, the record of what happened to it (164.312(b)).

**Lambda in the VPC with no NAT.** Closing GAP-05 by moving the Lambda into the starter's private subnets cuts its route to DynamoDB and S3. I used gateway VPC endpoints instead of a NAT gateway: they cost nothing and keep PHI on the AWS network. Each endpoint's policy allows only `PutItem` on the intake table and `PutObject` on the uploads bucket, and the security group allows HTTPS egress to those two endpoints only. A compromised function has no path to exfiltrate data to another bucket or the internet.

**Least privilege taken from the code.** The handler makes exactly two AWS calls, `put_item` and `put_object`. The role grants those two actions and nothing else, and `s3:PutObject` is scoped to the `uploads/` prefix.

**Two pipeline roles, with the split enforced by AWS rather than by YAML.** Pull requests assume `grc-pipeline-plan` (ReadOnlyAccess plus state read). `main` assumes `grc-pipeline-apply`. Each role's OIDC trust policy pins the GitHub subject claim, so a workflow edit in a PR cannot assume the apply role. The repo uses GitHub's immutable subject format (`repo:Owner@id/repo@id:...`), which pins the trust to numeric IDs: a renamed or re-created repo with the same name cannot inherit the roles. Both roles carry explicit denies on reading PHI and on weakening the evidence lock. The apply role can manage IAM only under the workload's `acme-health-intake-*` prefix, and the pipeline roles are named outside it, so the apply role cannot edit itself.

**Evidence is signed by identity, not by a key I manage.** Cosign keyless signing binds each bundle to `grc-gate.yml@refs/heads/main` in this repo through a Fulcio certificate, and records it in the public Rekor log. There is no private key to rotate, leak or keep in a secret. `scripts/verify-evidence.sh` checks the signer identity exactly; any valid GitHub signature is not enough.

**External verifiers get read access through the gate, too.** The vault is private. A grader or auditor is granted access by adding their principal to `evidence_readers`. That grants `GetObject`, `GetObjectVersion`, `GetObjectRetention` and `ListBucket` on the vault, and decryption through S3 on the audit key only; no write, delete or retention changes. Because the grant is a Terraform change, it goes through the policy gate and produces its own signed bundle. The record of who was given access to the evidence is itself evidence.

**Sign and Upload run on `main` even when Plan or Apply fails.** A failed apply is evidence too. Each bundle's `manifest.json` records the outcome of every step and a SHA-256 per file.

### Decisions the brief left to me

| Decision | Choice | Why |
|---|---|---|
| Region | us-east-1 | Same region as my lab vault and state; nothing in HIPAA constrains region |
| Object Lock mode | GOVERNANCE, 365 days | Pipeline roles are explicitly denied `s3:BypassGovernanceRetention`, so in practice the evidence is immutable to everything that writes it. GOVERNANCE still lets an account administrator tear down a sandbox after grading. Production: COMPLIANCE mode, 6 years, to meet 164.316(b)(2)(i). |
| Apply on merge vs manual approval | Apply on merge | The merge *is* the approval: the policy gate ran on the exact plan, and branch protection blocks merging without it (admins included). A second click adds latency without adding information. With more than one engineer I would require a PR review rather than a post-merge approval. |
| Single vs separate vault account | Single account | Acceptable for 30 days per the brief. The guardrail denies and the separate audit key carry most of the separation for now. |
| Terraform vs policy | Both, for every closed gap | See above |

## Control coverage

| Gap | HIPAA | Terraform fix | Policy | Status |
|---|---|---|---|---|
| GAP-01 S3 not under CMK | 164.312(a)(2)(iv) | `aws_s3_bucket_server_side_encryption_configuration.uploads` | `hipaa.s3_cmk_encryption` | Closed |
| GAP-02 DynamoDB not under CMK | 164.312(a)(2)(iv) | `server_side_encryption` on `aws_dynamodb_table.intake` | `hipaa.dynamodb_cmk_encryption` | Closed |
| GAP-03 No TLS-only policy | 164.312(e)(1) | `aws_s3_bucket_policy.uploads_tls_only` | `hipaa.s3_tls_only` | Closed |
| GAP-04 No versioning | 164.308(a)(7) | `aws_s3_bucket_versioning.uploads` | `hipaa.s3_versioning` | Closed |
| GAP-05 Lambda outside VPC | 164.312(e)(1) | `vpc_config` + `lambda_network.tf` | `hipaa.lambda_in_vpc` | Closed |
| GAP-06 No concurrency/DLQ/X-Ray | none | none | none | **Not addressed** (see below) |
| GAP-07 `dynamodb:*` / `s3:*` | 164.312(a)(1) | `data.aws_iam_policy_document.lambda_inline` | `hipaa.iam_least_privilege` | Closed |
| GAP-08 No API access logging | 164.312(b) | `access_log_settings` + `aws_cloudwatch_log_group.api_access` | `hipaa.api_access_logging` | Closed (logging and throttling; not WAF) |

The OSCAL component claims seven HIPAA controls. Four are implemented: 164.312(a)(2)(iv), (b), (c)(1) and (e)(1). Three are partial, each with the reason stated in its remarks:

- **164.312(a)(1)**: covers service access only; the API has no caller authentication.
- **164.308(a)(7)**: covers S3 versioning only; no DynamoDB point-in-time recovery and no DR plan.
- **164.316(b)(2)(i)**: retention is 365 days, not the required 6 years.

The policies apply to every bucket, table, function, IAM policy and stage in the plan, not only the starter's. The evidence vault and CloudTrail bucket are gated by the same rules. The bootstrap state bucket follows them too, but sits outside the gated plan.

## Trade-offs I accepted

- **PowerUserAccess on the apply role.** It is broad. Writing a least-privilege policy for everything Terraform touches here (KMS, VPC, endpoints, Lambda, API Gateway, Logs, CloudTrail, S3, DynamoDB) would have taken most of a week and broken on every new resource type. I contained it instead: IAM only under the workload prefix, explicit denies on PHI reads and evidence deletion, and only `main` can assume it.
- **Pull-request runs do not go to the vault.** The plan role is read-only by design, so PR evidence (including the red PR's denial) lives as a 90-day Actions artifact plus the PR history, not in Object Lock. Only `main` runs, which change infrastructure, are signed and retained.
- **A self-authored HIPAA catalog.** NIST publishes no OSCAL catalog for the Security Rule, and SP 800-66r2 is guidance rather than a catalog. I wrote a seven-control catalog containing only the sections I claim, with the regulatory text and eCFR links, and SP 800-66r2 cited as the interpretation guide. Its remarks say so. Pointing `source` at the NIST 800-53 catalog would have been easier and would have described a framework I didn't declare.
- **Policies read the root module only.** The workload has no child modules. A module-based refactor would need the helpers in `policies/lib/tfplan.rego` to walk `module_calls`.
- **Bootstrap state is local.** Something has to exist before the pipeline can run. The bootstrap stack (state bucket, pipeline roles) was applied once by hand and its state is kept outside the repo.

## With another sprint

1. **Authenticate API callers** (Cognito or an IAM/JWT authorizer on `POST /intake`). This is the largest real HIPAA gap left, and it is what keeps 164.312(a)(1) at partial.
2. **Move the vault to a separate log-archive account** in COMPLIANCE mode with 6-year retention, which closes 164.316(b)(2)(i).
3. **DynamoDB point-in-time recovery**, plus a policy requiring it, to finish 164.308(a)(7)'s backup specification.
4. **Close GAP-06** (reserved concurrency, an encrypted SQS DLQ, X-Ray through an interface endpoint) as an availability control mapped to SOC 2 A1 / CC7.2.
5. **Commit the gap regression harness** I used during development, and run it on a schedule against an empty account so the fresh-plan behaviour is checked continuously, not once.

## What I didn't get to

- **GAP-06.** None of reserved concurrency, a dead-letter queue or tracing maps to a HIPAA Security Rule section. `GAPS.md` cites only SOC 2 and CMMC for it. Closing it would be good engineering, but claiming it as a HIPAA control would be inaccurate, so it is left open and unclaimed.
- **WAF on the API.** AWS WAF cannot attach to API Gateway HTTP APIs, only REST APIs, CloudFront and ALB. GAP-08 is closed for logging and throttling; WAF would need the API in front of CloudFront or rebuilt as a REST API.
- **Activity review (164.308(a)(1)(ii)(D)).** CloudTrail and access logs capture activity, but no one reviews them on a schedule. It's a process, not code, and I haven't claimed it.
- **AWS Config / Security Hub.** I built these in Lab 5.2 but left them out here to keep the scope on what the brief grades.
