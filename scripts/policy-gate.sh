#!/usr/bin/env bash
# scripts/policy-gate.sh — run the HIPAA policy suite against a Terraform plan.
#
# Usage: scripts/policy-gate.sh <plan.json> [evidence_dir]
#
# 1. opa test: the policies' own unit tests must pass (a broken policy
#    that silently allows everything must not be trusted as a gate).
# 2. conftest: every policy namespace runs against the plan.
# Results are written to the evidence dir. Exits non-zero on any failure:
# the gate fails closed.
set -euo pipefail

PLAN_JSON="${1:?usage: policy-gate.sh <plan.json> [evidence_dir]}"
EVIDENCE_DIR="${2:-evidence}"
POLICY_DIR="$(cd "$(dirname "$0")/.." && pwd)/policies"
mkdir -p "$EVIDENCE_DIR"

echo "== opa test ($POLICY_DIR)"
opa test "$POLICY_DIR" --format json > "$EVIDENCE_DIR/opa-test-results.json" || {
  opa test "$POLICY_DIR" -v || true
  echo "policy-gate: FAIL (policy unit tests failing)"
  exit 1
}
opa test "$POLICY_DIR"

echo "== conftest (all hipaa.* namespaces)"
set +e
conftest test --all-namespaces --policy "$POLICY_DIR" --output json "$PLAN_JSON" \
  > "$EVIDENCE_DIR/conftest-results.json"
STATUS=$?
set -e

# Human-readable view in the job log, with the HIPAA citation first.
conftest test --all-namespaces --policy "$POLICY_DIR" --no-color "$PLAN_JSON" || true

if [[ $STATUS -eq 0 ]]; then
  echo "policy-gate: PASS"
else
  echo "policy-gate: FAIL (see $EVIDENCE_DIR/conftest-results.json)"
fi
exit $STATUS
