#!/usr/bin/env bash
# scripts/validate-oscal.sh — validate the OSCAL models with compliance-trestle.
#
# Usage: scripts/validate-oscal.sh [evidence_dir]
#
# Imports catalog, profile and component definition into a throwaway trestle
# workspace, runs `trestle validate` on each, then resolves the profile
# against the catalog to prove every selected control exists.
# Requires: pip install compliance-trestle (tested with v5.2.0, OSCAL 1.2.1)
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
EVIDENCE_DIR="${1:-}"
TRESTLE="${TRESTLE:-trestle}"
WS=$(mktemp -d); trap 'rm -rf "$WS"' EXIT

cd "$WS"
"$TRESTLE" init >/dev/null
"$TRESTLE" import -f "$REPO/oscal/catalogs/hipaa-security-rule.json" -o hipaa-security-rule
"$TRESTLE" import -f "$REPO/oscal/profiles/hipaa-intake-baseline.json" -o hipaa-intake-baseline
"$TRESTLE" import -f "$REPO/oscal/components/acme-health-intake.json" -o acme-health-intake

# The profile's relative href points at the repo layout; inside the
# workspace, point it at the imported catalog.
python3 - <<'EOF'
import json
p = "profiles/hipaa-intake-baseline/profile.json"
d = json.load(open(p))
d["profile"]["imports"][0]["href"] = "trestle://catalogs/hipaa-security-rule/catalog.json"
json.dump(d, open(p, "w"), indent=2)
EOF

OUT=$("$TRESTLE" validate -a 2>&1); echo "$OUT"
grep -q "VALID" <<<"$OUT" && ! grep -qi "invalid\|error" <<<"$OUT"

"$TRESTLE" author profile-resolve -n hipaa-intake-baseline -o hipaa-intake-resolved >/dev/null
RESOLVED=$(python3 -c "
import json
c = json.load(open('catalogs/hipaa-intake-resolved/catalog.json'))['catalog']
ids = sorted(x['id'] for g in c.get('groups', []) for x in g.get('controls', []))
print(len(ids), ' '.join(ids))")
echo "Profile resolves to $RESOLVED"

if [[ -n "$EVIDENCE_DIR" ]]; then
  mkdir -p "$EVIDENCE_DIR"
  { echo "$OUT"; echo "Profile resolves to $RESOLVED"; } > "$EVIDENCE_DIR/trestle-validate.txt"
fi
echo "oscal: VALID"
