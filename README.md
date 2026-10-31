# Acme Health Patient Intake API: governed

The [cgep-app-starter](https://github.com/GRCEngClub/cgep-app-starter) workload, made audit-defensible against the **HIPAA Security Rule**. The design reasoning is in **[WRITEUP.md](WRITEUP.md)**.

Every push to `main` is planned, checked against seven HIPAA policies, applied, signed with Cosign (keyless, GitHub OIDC), and filed in an S3 Object Lock vault.

## Verify the evidence

Requires `aws`, `cosign` v2 and `jq`.

**Vault access for graders.** The vault is private. Send me the IAM principal ARN you'll verify from. I add it to `evidence_readers` in [terraform/variables.tf](terraform/variables.tf) through a PR, and the pipeline grants read-only access: `GetObject`, `GetObjectVersion`, `GetObjectRetention` and `ListBucket` on the vault, plus `kms:Decrypt` through S3 on the audit key. Your own IAM policy also needs to allow those actions on `arn:aws:s3:::acme-health-intake-evidence-fcc40870` and `arn:aws:kms:us-east-1:697020387897:key/fe81b92d-7b15-451f-a674-230e60ac5613`. Then run the script with `--profile <yours>`.

```bash
scripts/verify-evidence.sh latest            # most recent run on main
scripts/verify-evidence.sh <run_id>-<attempt> # a specific run
```

Three checks, all must pass:

| Check | How |
|---|---|
| Integrity | SHA-256 of the bundle is recomputed and compared with the stored `.sha256` |
| Authenticity | `cosign verify-blob` against the public Sigstore/Rekor log, requiring the signer `…/cgep-app-starter/.github/workflows/grc-gate.yml@refs/heads/main` |
| Preservation | `s3api get-object-retention` shows Object Lock retention still in force |

Expected output ends with `CHAIN INTACT for run …`, followed by the bundle's manifest (commit, framework and step outcomes).

The same bundle, `.sig.bundle` and `receipt.json` are attached to each `main` run under *Artifacts* for 90 days, so the signature and hash can be checked without AWS access.

## Verify the gate

```bash
opa test ./policies                                   # 25/25
scripts/policy-gate.sh <plan.json>                    # conftest, all hipaa.* namespaces
scripts/validate-oscal.sh                             # trestle validate + profile resolution
```

- PR **#3** passed the gate and merged.
- PR **#4** re-introduces GAP-07 (`dynamodb:*`), fails `hipaa.iam_least_privilege` (HIPAA 164.312(a)(1)), and is blocked from merging by branch protection.

## Layout

```
terraform/      workload + HIPAA baseline (KMS, vault, CloudTrail, gap overrides), S3 backend
bootstrap/      state bucket + plan/apply OIDC roles (applied once, by hand)
policies/       hipaa.* Rego policies, lib/ helpers, tests/
oscal/          catalog (HIPAA subset), profile, component definition
scripts/        policy-gate.sh, validate-oscal.sh, verify-evidence.sh
.github/workflows/grc-gate.yml   Plan, Policy check, Apply, Sign, Upload
```

Starter docs: [WORKLOAD.md](WORKLOAD.md), [GAPS.md](GAPS.md), [FRAMEWORKS.md](FRAMEWORKS.md). Infrastructure changes go through the pipeline; `make deploy` is for the original starter only.
