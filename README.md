# Acme Health Patient Intake API: governed

The [cgep-app-starter](https://github.com/GRCEngClub/cgep-app-starter) workload, made audit-defensible against the **HIPAA Security Rule**. The design reasoning is in **[WRITEUP.md](WRITEUP.md)**.

Every push to `main` is planned, checked against seven HIPAA policies, applied, signed with Cosign (keyless, GitHub OIDC), and filed in an S3 Object Lock vault. A daily scheduled run checks live infrastructure for drift and files a signed bundle even when nothing changed.

## Set up and run

Prerequisites: Terraform ≥ 1.10, AWS CLI v2, OPA 1.x, Conftest, Cosign v2, `gh`, `jq`, and `pip install compliance-trestle==5.2.0`.

1. **Bootstrap (once, by hand).** Creates the state bucket and the two GitHub OIDC roles.
   ```bash
   cd bootstrap && terraform init && terraform apply
   ```
   Set `github_sub_prefix` to your repo's OIDC subject (`gh api repos/<owner>/<repo>/actions/oidc/customization/sub`).
2. **Point the workload at that state.** Put the `state_bucket` and `state_kms_key_arn` outputs into [terraform/backend.tf](terraform/backend.tf). Backend blocks cannot read variables, so these are literal values.
3. **Give GitHub the role ARNs and vault name.**
   ```bash
   gh variable set AWS_PLAN_ROLE_ARN  --body "<plan_role_arn>"
   gh variable set AWS_APPLY_ROLE_ARN --body "<apply_role_arn>"
   gh variable set EVIDENCE_BUCKET    --body "<evidence bucket>"
   ```
4. **Deploy through the pipeline.** Open a PR (plan and policy check run), then merge (apply, sign, upload). Do not run `terraform apply` on `terraform/` by hand.
5. **Smoke test.** `make test` returns `{"submission_id": "...", "status": "received"}`.

Run the checks locally:

```bash
opa test ./policies                          # policy unit tests (positive + negative per control)
(cd terraform && terraform plan -out=tfplan && terraform show -json tfplan > plan.json)
scripts/policy-gate.sh terraform/plan.json   # HIPAA policy gate
scripts/gap-regression.py                    # re-introduce each gap, confirm the gate blocks it
scripts/validate-oscal.sh                    # OSCAL validation
```

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
python3 -m unittest discover -s tests/detections -v   # 22 detection-rule cases vs real EventBridge
scripts/gap-regression.py                             # each closed gap re-introduced -> blocked
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
