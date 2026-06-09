#!/usr/bin/env bash
#
# run-all.sh — run all three Miasma / Shai-Hulud read-only scans in sequence,
# tee a combined log, and exit with the WORST result code of the three.
#
# Detection only: nothing here edits, removes, or rotates anything.

set -uo pipefail

# run-all needs the sibling scripts on disk, so it cannot be piped (curl | bash);
# clone the repo to use it. Resolve our directory, falling back to $PWD.
SRC="${BASH_SOURCE[0]:-}"
if [ -n "$SRC" ] && [ -f "$SRC" ]; then
  SCRIPT_DIR="$(cd "$(dirname "$SRC")" && pwd)"
else
  SCRIPT_DIR="$PWD"
fi
OUTBASE="${MIASMA_OUT_DIR:-$SCRIPT_DIR}"

SCANS=(
  miasma-audit-hardened.sh
  miasma-persistence-scan.sh
  miasma-npm-supplychain-scan.sh
)

usage() {
  cat <<EOF
run-all.sh — run every Miasma / Shai-Hulud read-only scan and summarise

USAGE:
  run-all.sh [OPTIONS] [ROOT]
  run-all.sh -h | --help

Runs, in order:
  ${SCANS[*]}

ARGS:
  ROOT                Directory tree to scan (default: \$HOME). Forwarded to each scan.

OPTIONS (forwarded to each scan):
  --copy-evidence     Preserve copies of flagged files (may contain secrets/payloads)
  --offline           Skip network (npm-registry publish-date lookup)
  -h, --help          Show this help

ENV:
  MIASMA_OUT_DIR=DIR  Where each scan's folder and the combined log are written
                      (default: next to these scripts)

EXIT CODE (worst of the three scans):
  2  [!!] confirmed indicator — assume compromised
  1  [!]  suspicious — needs manual review
  0  clean of the on-host indicators these scans check (not a guarantee)

If anything is flagged: do NOT rotate from this machine. Clean it FIRST, then
rotate credentials from a DIFFERENT trusted device.
EOF
}

# Only intercept --help; everything else is forwarded verbatim to each scan.
for a in "$@"; do
  case "$a" in -h | --help)
    usage
    exit 0
    ;;
  esac
done

LOG="$OUTBASE/miasma-run-all-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$OUTBASE"

# run_scan <script> [scan-args...]: run one sibling scan, banner + output + exit
# line all tee'd to the combined log. Returns the scan's exit code (1 if missing).
run_scan() {
  local s="$1"
  shift
  local path="$SCRIPT_DIR/$s" rc
  if [ ! -x "$path" ]; then
    printf '!! SKIP: %s not found or not executable\n' "$s" | tee -a "$LOG"
    return 1
  fi
  {
    printf '\n############################################################\n'
    printf '## %s\n' "$s"
    printf '############################################################\n'
  } | tee -a "$LOG"
  "$path" "$@" 2>&1 | tee -a "$LOG"
  rc=${PIPESTATUS[0]}
  printf -- '---- %s exit: %s ----\n' "$s" "$rc" | tee -a "$LOG"
  return "$rc"
}

worst=0
for s in "${SCANS[@]}"; do
  run_scan "$s" "$@"
  rc=$?
  [ "$rc" -gt "$worst" ] && worst="$rc"
done

case "$worst" in
2) summary="OVERALL: COMPROMISE INDICATORS ([!!]). Clean the machine FIRST, then rotate from a trusted device." ;;
1) summary="OVERALL: SUSPICIOUS artifacts ([!]) need manual review." ;;
*) summary="OVERALL: clean of the on-host indicators these scans check (not a guarantee)." ;;
esac

{
  printf '\n============================================================\n'
  printf '%s\n' "$summary"
  printf 'Combined log: %s\n' "$LOG"
  printf '============================================================\n'
} | tee -a "$LOG"

exit "$worst"
