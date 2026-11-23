#!/usr/bin/env python3
"""Integration test for the policy gate: re-introduce each closed gap into a
copy of the real Terraform, plan it against live state, and confirm the gate
blocks it on exactly the matching HIPAA policy and no other.

This is the grader's "re-introduce a gap and confirm the gate fires" check,
run for every gap the repo claims.

Usage:  scripts/gap-regression.py
Needs:  terraform, conftest, AWS credentials that can read the state bucket,
        and an initialised terraform/ directory (terraform init).
Takes a few minutes: one terraform plan per gap.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "terraform")
POLICIES = os.path.join(REPO, "policies")

# The starter's original GAP-07 shape: jsonencode over ARNs, wildcard actions.
ORIGINAL_GAP_07 = '''resource "aws_iam_role_policy" "lambda_inline" {
  name = "intake-data-access"
  role = aws_iam_role.lambda.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "dynamodb:*", Resource = aws_dynamodb_table.intake.arn },
      { Effect = "Allow", Action = "s3:*", Resource = ["${aws_s3_bucket.uploads.arn}", "${aws_s3_bucket.uploads.arn}/*"] }
    ]
  })
}
'''


def drop_block(text, header):
    """Remove the HCL block that starts with `header`."""
    start = text.index(header)
    depth = 0
    for i in range(text.index("{", start), len(text)):
        depth += {"{": 1, "}": -1}.get(text[i], 0)
        if depth == 0:
            return text[:start] + text[i + 1:]
    raise ValueError(f"unbalanced block: {header}")


def sub_once(pattern, repl):
    def apply(text):
        new, n = re.subn(pattern, repl, text, count=1)
        if n != 1:
            raise ValueError(f"pattern not found: {pattern}")
        return new
    return apply


# gap -> (expected policy namespace, file to edit, edit)
MUTATIONS = {
    "GAP-01": ("hipaa.s3_cmk_encryption", "s3_uploads_hardening.tf",
               sub_once(r'sse_algorithm(\s+)= "aws:kms"', r'sse_algorithm\1= "AES256"')),
    "GAP-02": ("hipaa.dynamodb_cmk_encryption", "main.tf",
               lambda t: drop_block(t, "  server_side_encryption {")),
    "GAP-03": ("hipaa.s3_tls_only", "s3_uploads_hardening.tf",
               lambda t: drop_block(t, 'resource "aws_s3_bucket_policy" "uploads_tls_only"')),
    "GAP-04": ("hipaa.s3_versioning", "s3_uploads_hardening.tf",
               sub_once(r'(versioning_configuration \{\s+status\s+= )"Enabled"', r'\1"Suspended"')),
    "GAP-05": ("hipaa.lambda_in_vpc", "main.tf",
               lambda t: drop_block(t, "  vpc_config {")),
    "GAP-07": ("hipaa.iam_least_privilege", "main.tf",
               lambda t: drop_block(drop_block(t, 'data "aws_iam_policy_document" "lambda_inline"'),
                                    'resource "aws_iam_role_policy" "lambda_inline"') + ORIGINAL_GAP_07),
    "GAP-08": ("hipaa.api_access_logging", "main.tf",
               lambda t: drop_block(t, "  access_log_settings {")),
}


def run(cwd, *args):
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def main():
    if not os.path.isdir(os.path.join(SRC, ".terraform")):
        sys.exit("terraform/ is not initialised; run `terraform -chdir=terraform init` first")

    ok = True
    for gap, (expected, filename, mutate) in MUTATIONS.items():
        with tempfile.TemporaryDirectory() as tmp:
            work = os.path.join(tmp, "terraform")
            # Keep .terraform/ (providers + backend metadata); skip plan output.
            shutil.copytree(SRC, work, ignore=shutil.ignore_patterns("tfplan", "plan.json"))
            path = os.path.join(work, filename)
            with open(path) as f:
                mutated = mutate(f.read())
            with open(path, "w") as f:
                f.write(mutated)

            plan = run(work, "terraform", "plan", "-refresh=false", "-lock=false", "-input=false", "-out=tfplan")
            if plan.returncode:
                print(f"{gap}: PLAN ERROR\n{plan.stderr[-800:]}")
                ok = False
                continue
            with open(os.path.join(work, "plan.json"), "w") as f:
                f.write(run(work, "terraform", "show", "-json", "tfplan").stdout)

            gate = run(work, "conftest", "test", "--all-namespaces", "-p", POLICIES, "-o", "json", "plan.json")
            fired = sorted({r["namespace"] for r in json.loads(gate.stdout) for x in (r.get("failures") or [])})
            passed = gate.returncode != 0 and fired == [expected]
            ok &= passed
            print(f"{gap}: gate {'BLOCKED' if gate.returncode else 'ALLOWED'} by {fired or 'nothing'} "
                  f"-> {'PASS' if passed else 'FAIL (expected ' + expected + ')'}")

    print("gap-regression:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
