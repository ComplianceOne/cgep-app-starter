#!/usr/bin/env bash
# scripts/verify-evidence.sh — verify one pipeline run's evidence end to end.
#
# Usage: scripts/verify-evidence.sh <run_id>-<attempt> [--vault <bucket>] [--profile <aws-profile>]
#        scripts/verify-evidence.sh latest [--vault <bucket>]
#
# Three checks, all must hold:
#   1. Integrity     SHA-256 of the bundle matches the recorded hash
#   2. Authenticity  Cosign signature verifies against the public Sigstore
#                    log, and the signer is this repo's grc-gate workflow on main
#   3. Preservation  Object Lock retention is active on the stored bundle
set -euo pipefail

RUN="${1:?usage: verify-evidence.sh <run_id>-<attempt>|latest [--vault <bucket>] [--profile <p>]}"
shift
VAULT="${EVIDENCE_BUCKET:-acme-health-intake-evidence-fcc40870}"
REPO="${GITHUB_REPOSITORY:-ComplianceOne/cgep-app-starter}"
AWS=(aws)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) AWS=(aws --profile "$2"); shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if command -v sha256sum >/dev/null 2>&1; then SHASUM=(sha256sum); else SHASUM=(shasum -a 256); fi

if [[ "$RUN" == "latest" ]]; then
  RUN=$("${AWS[@]}" s3api list-objects-v2 --bucket "$VAULT" --prefix runs/ \
        --query 'sort_by(Contents[?ends_with(Key, `receipt.json`)], &LastModified)[-1].Key' --output text \
        | cut -d/ -f2)
fi
PREFIX="runs/${RUN}"
echo "Verifying s3://${VAULT}/${PREFIX}/"

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
"${AWS[@]}" s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive --only-show-errors
BUNDLE=$(ls evidence-*.tar.gz | head -1)

# 1. Integrity
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$("${SHASUM[@]}" "$BUNDLE" | awk '{print $1}')
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "FAIL integrity: $ACTUAL != $EXPECTED"; exit 1; }
echo "PASS integrity     sha256 $ACTUAL"

# 2. Authenticity — pinned to this repo's workflow on main, not any signer.
cosign verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity "https://github.com/${REPO}/.github/workflows/grc-gate.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$BUNDLE" >/dev/null
echo "PASS authenticity  signed by ${REPO} grc-gate.yml@main (Rekor-logged)"

# 3. Preservation
read -r MODE UNTIL < <("${AWS[@]}" s3api get-object-retention --bucket "$VAULT" --key "${PREFIX}/${BUNDLE}" \
  --query '[Retention.Mode, Retention.RetainUntilDate]' --output text)
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
[[ "$UNTIL" > "$NOW" ]] || { echo "FAIL preservation: retention expired $UNTIL"; exit 1; }
echo "PASS preservation  Object Lock ${MODE} until ${UNTIL}"

echo "CHAIN INTACT for run ${RUN}"
tar -xzf "$BUNDLE" manifest.json && jq '{commit, created_utc, framework, steps}' manifest.json
