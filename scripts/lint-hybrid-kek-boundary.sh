#!/usr/bin/env bash
# lint-hybrid-kek-boundary.sh — CM-25 / F11 anti-recurrence gate.
# -----------------------------------------------------------------------------
# Per SPEC_CM25_F11_COMBINER_EXPORT.md §7 (I-9 note) and
# sdk/loggie-sdk's ratified CM-25 design record §6: the conjunctive-hybrid
# invariant is enforced by the COMBINATION of (a) one math home, (b) this
# lint, (c) the withhold-either-secret invariant test, (d) doctrine — NOT
# by the export shape alone. pqc-shared still exports the low-level
# primitives (x25519SharedSecret, hkdfSha256, secretboxRaw, pqcEncapsulate,
# pqcWrapFromSharedSecret) that single-primitive schemes legitimately need
# and from which an OR-combiner could be reassembled by a careless caller.
#
# Scope of THIS gate: pqc-shared's OWN src/ tree only. It guards against a
# second hybrid-KEK derivation appearing anywhere in this package outside
# the one sanctioned home (src/crypto/hybrid.ts's deriveCombinedKek core +
# its two profile adapters). It does NOT scan consumer repos (loggie-sdk
# etc.) — that is a separate, consumer-side gate (mirroring loggie-sdk's
# lint:nacl-boundary / lint:module-resolution family) to be added when
# loggie.hybrid.v3 is implemented; out of scope for this pqc-shared-only
# tranche.
#
# Gates (both MUST hold):
#   1. No file other than the allowlisted set below both (a) calls
#      `hkdfSha256(` and (b) mentions "hybrid" (case-insensitive) anywhere
#      in that file — the co-occurrence signal for "this file derives a
#      hybrid-shaped KEK". Checked file-wide (not line-by-line): a
#      combiner's salt/info construction is rarely on the same source line
#      as its hkdfSha256 call.
#   2. src/crypto/hybrid.ts itself has exactly ONE hybrid-KEK-deriving
#      function (deriveCombinedKek) — if a second HKDF-based KEK deriver
#      appears in that file, that's a silent second combiner, exactly the
#      CM-25/PQC-09 recurrence class.
#
# Allowlist: scripts/lint-hybrid-kek-boundary.allowlist
#   - flat file, one path per line; each entry MUST document why it's safe
#   - ONLY for combiners already verified AND-combined (not OR) via manual
#     read of the implementation — never allowlist an unaudited hit
#
# Exit code: 0 when clean, 1 on any non-allowlisted violation.
# -----------------------------------------------------------------------------

set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || echo "$(dirname "$0")/..")"

ALLOWLIST_FILE="scripts/lint-hybrid-kek-boundary.allowlist"
VIOLATIONS=0

ALLOWLIST_PATTERNS=()
if [ -f "$ALLOWLIST_FILE" ]; then
  while IFS= read -r line; do
    stripped="${line%%#*}"
    stripped="$(echo -n "$stripped" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [ -z "$stripped" ] && continue
    ALLOWLIST_PATTERNS+=("$stripped")
  done < "$ALLOWLIST_FILE"
fi

is_allowlisted() {
  local path="$1"
  for pat in "${ALLOWLIST_PATTERNS[@]+"${ALLOWLIST_PATTERNS[@]}"}"; do
    case "$path" in
      *"$pat"*) return 0 ;;
    esac
  done
  return 1
}

echo "== Gate 1: hybrid-KEK derivation confined to src/crypto/hybrid.ts (+ allowlist) =="
while IFS= read -r f; do
  [ -z "$f" ] && continue
  case "$f" in
    src/crypto/hybrid.ts) continue ;;
    *node_modules/*|*/dist/*|*/build/*) continue ;;
    *.ts|*.tsx|*.js|*.jsx|*.mjs|*.cjs) ;;
    *) continue ;;
  esac
  is_allowlisted "$f" && continue
  if grep -q "hkdfSha256(" "$f" 2>/dev/null && grep -qi "hybrid" "$f" 2>/dev/null; then
    echo "VIOLATION $f: calls hkdfSha256( and mentions \"hybrid\" — possible undeclared hybrid-KEK combiner"
    VIOLATIONS=$((VIOLATIONS + 1))
  fi
done < <(git ls-files 'src/*' 2>/dev/null)

echo "== Gate 2: exactly one hybrid-KEK-deriving function in hybrid.ts =="
DERIVER_COUNT=$(grep -cE "^(export )?function derive.*Kek|^(export )?function.*combinedKek" src/crypto/hybrid.ts 2>/dev/null || echo 0)
if [ "$DERIVER_COUNT" -ne 1 ]; then
  echo "VIOLATION: expected exactly 1 KEK-deriving function in src/crypto/hybrid.ts, found $DERIVER_COUNT"
  VIOLATIONS=$((VIOLATIONS + 1))
else
  echo "OK: exactly 1 (deriveCombinedKek)"
fi

echo ""
if [ "$VIOLATIONS" -eq 0 ]; then
  echo "lint-hybrid-kek-boundary: clean. No non-allowlisted hits."
  exit 0
fi

echo "lint-hybrid-kek-boundary: $VIOLATIONS violation(s)."
echo ""
echo "A second hybrid-KEK derivation site is exactly the CM-25/PQC-09 defect"
echo "class (independent combiner implementations that can silently diverge"
echo "into an OR-combined wrap). Route all hybrid-KEK derivation through"
echo "deriveCombinedKek in src/crypto/hybrid.ts."
exit 1
