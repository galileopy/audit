#!/usr/bin/env bash
#
# Miasma / Shai-Hulud npm supply-chain scan (companion to miasma-audit-hardened.sh)
# -------------------------------------------------------------------------------
# Detection only. NEVER edits, removes, or rotates anything.
# Covers npm surface NOT in the original checklist:
#   - package.json lifecycle scripts (preinstall/install/postinstall/prepare)
#   - ~/.npmrc (injected registry, exposed auth token)
#   - affected packages in GLOBAL / nvm node_modules outside $HOME
# Clean the machine FIRST, then rotate from a DIFFERENT trusted device.

set -uo pipefail

# Resolve our own directory; fall back to $PWD when piped in (curl | bash),
# where there is no script file on disk.
SRC="${BASH_SOURCE[0]:-}"
if [ -n "$SRC" ] && [ -f "$SRC" ]; then
  SCRIPT_DIR="$(cd "$(dirname "$SRC")" && pwd)"
else
  SCRIPT_DIR="$PWD"
fi

usage() {
  cat <<EOF
miasma-npm-supplychain-scan.sh — read-only Miasma / Shai-Hulud npm supply-chain scan

USAGE:
  miasma-npm-supplychain-scan.sh [OPTIONS] [ROOT]
  miasma-npm-supplychain-scan.sh -h | --help

Scans package.json lifecycle scripts, ~/.npmrc, and global/nvm node_modules.

ARGS:
  ROOT                Directory tree to scan (default: \$HOME)

OPTIONS:
  --copy-evidence     Same as COPY_EVIDENCE=1 (preserve flagged files)
  --offline           Accepted for wrapper compatibility (queries no registry)
  -h, --help          Show this help

ENV (flags above take precedence):
  COPY_EVIDENCE=1     Preserve copies of flagged files (may contain secrets/payloads)
  MIASMA_OUT_DIR=DIR  Write the output folder here (default: next to this script)

EXIT CODES:
  2  [!!] worm marker found   1  [!] suspicious, review   0  clean (not a guarantee)

Detection only: never edits, removes, or rotates anything.
EOF
}

COPY_EVIDENCE="${COPY_EVIDENCE:-0}"
ROOT=""
while [ $# -gt 0 ]; do
  case "$1" in
  -h | --help)
    usage
    exit 0
    ;;
  --copy-evidence) COPY_EVIDENCE=1 ;;
  --offline) : ;; # accepted for wrapper compatibility; queries no registry
  --)
    shift
    [ $# -gt 0 ] && ROOT="$1"
    break
    ;;
  -*)
    echo "unknown option: $1" >&2
    usage
    exit 64
    ;;
  *) if [ -z "$ROOT" ]; then ROOT="$1"; else
    echo "unexpected arg: $1" >&2
    exit 64
  fi ;;
  esac
  shift
done
ROOT="${ROOT:-$HOME}"

OUTBASE="${MIASMA_OUT_DIR:-$SCRIPT_DIR}"
OUT="$OUTBASE/miasma-npm-supplychain-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT/evidence"

AFFECTED_PKGS=(
  "@redhat-cloud-services" "@vapi-ai/server-sdk" "ai-sdk-ollama"
  "autotel" "awaitly" "executable-stories" "node-env-resolver"
  "wrangler-deploy" "mountly"
)
# Definitive worm markers ([!!]); generic dropper commands ([!] review).
MARKERS='Miasma|Shai-Hulud|api\.anthropic\.com/v1/api|__FAKE_PLATFORM__|TESTING_TAR_FAKE_PLATFORM|SKIP_DOMAIN|bypass_2fa'
SUSPICIOUS='curl |wget |base64 -d|base64 --decode|node -e|node --eval|bun |/dev/tcp/|eval\(|child_process|setup\.(js|mjs)'
LIFECYCLE_RE='"(preinstall|install|postinstall|prepare|prepublish|prepublishOnly)"'

# Severity counters drive the exit code: [!!]=confirmed/critical, [!]=review.
CRIT=0
WARN=0
report() {
  case "$*" in
  *"[!!]"*) CRIT=$((CRIT + 1)) ;;
  *"[!]"*) WARN=$((WARN + 1)) ;;
  esac
  printf '%s\n' "$*" | tee -a "$OUT/report.txt"
}

# report_indented: report each line of stdin as an indented detail line beneath a
# finding header. Call with process substitution (report_indented < <(...)) so it
# runs in this shell and report()'s counters are preserved.
report_indented() {
  local l
  while IFS= read -r l; do report "      $l"; done
}

# Evidence copying is OPT-IN (COPY_EVIDENCE / --copy-evidence); copied files may
# contain live payloads or secrets.
copy_evidence() {
  [ "$COPY_EVIDENCE" = "1" ] || return 0
  local f="$1" safe
  safe="${f//\//_}"
  cp "$f" "$OUT/evidence/$safe" 2>/dev/null || true
}

have() { command -v "$1" >/dev/null 2>&1; }
HAVE_JQ=0
have jq && HAVE_JQ=1
HAVE_NPM=0
have npm && HAVE_NPM=1

# Reusable prune so no find re-ingests an audit output directory, matched by
# NAME so it works wherever MIASMA_OUT_DIR points.
SKIP_OUT=(-type d \( -name 'miasma-shaihulud-audit-*' -o -name 'miasma-persistence-*' -o -name 'miasma-npm-supplychain-*' \) -prune -o)

# scan_lifecycle_jq <package.json>: authoritative check — pull only the lifecycle
# script values via jq, then match (worm marker -> [!!]; dropper command -> [!]).
scan_lifecycle_jq() {
  local pj="$1" scripts sev=""
  scripts="$(jq -r '
    .scripts // {} | to_entries[]
    | select(.key|test("^(pre|post)?(install|prepare|prepublish)"))
    | "\(.key): \(.value)"' "$pj" 2>/dev/null)"
  [ -n "$scripts" ] || return 0
  if printf '%s' "$scripts" | grep -EqsI "$MARKERS"; then
    sev="!!"
  elif printf '%s' "$scripts" | grep -EqsI "$SUSPICIOUS"; then
    sev="!"
  fi
  [ -n "$sev" ] || return 0
  report "[$sev] Suspicious lifecycle script in $pj:"
  report_indented < <(printf '%s\n' "$scripts" | grep -EI "$MARKERS|$SUSPICIOUS")
  copy_evidence "$pj"
}

# scan_lifecycle_grep <package.json>: fallback when jq is absent — match a
# lifecycle key and a payload tell on one line.
scan_lifecycle_grep() {
  local pj="$1" sev=""
  if grep -EqsI "$LIFECYCLE_RE.*($MARKERS)" "$pj" 2>/dev/null; then
    sev="!!"
  elif grep -EqsI "$LIFECYCLE_RE.*($SUSPICIOUS)" "$pj" 2>/dev/null; then
    sev="!"
  fi
  [ -n "$sev" ] || return 0
  report "[$sev] Suspicious lifecycle script (grep) in $pj:"
  report_indented < <(grep -EnsI "$LIFECYCLE_RE.*($MARKERS|$SUSPICIOUS)" "$pj" 2>/dev/null)
  copy_evidence "$pj"
}

echo "npm supply-chain audit output: $OUT"
echo "(read-only: this script does not modify, remove, or rotate anything)"
echo "(evidence copying is opt-in: set COPY_EVIDENCE=1 to preserve flagged files)"
echo
report "=== Miasma / Shai-Hulud npm supply-chain scan (read-only) ==="
report "Started: $(date '+%Y-%m-%dT%H:%M:%S%z')"
report "Root: $ROOT"
miss=""
[ "$HAVE_JQ" = "1" ] || miss="$miss jq"
[ "$HAVE_NPM" = "1" ] || miss="$miss npm"
[ -n "$miss" ] && report "[i] Missing tools (related checks downgraded):$miss"
report ""

# -----------------------------------------------------------------------------
# 1. package.json lifecycle scripts with suspicious commands
#    (the first wave's vector: a postinstall that fetches/executes a payload)
# -----------------------------------------------------------------------------
report "=== package.json lifecycle scripts ==="
while IFS= read -r pj; do
  if [ "$HAVE_JQ" = "1" ]; then scan_lifecycle_jq "$pj"; else scan_lifecycle_grep "$pj"; fi
done < <(find "$ROOT" "${SKIP_OUT[@]}" -type d -name node_modules -prune -false \
  -o -type f -name package.json -print 2>/dev/null)
report ""

# -----------------------------------------------------------------------------
# 2. ~/.npmrc — injected registry / exposed auth token
# -----------------------------------------------------------------------------
report "=== ~/.npmrc inspection ==="
# NOTE: .npmrc routinely holds live auth tokens, so it is NEVER copied to
# evidence; we only report the offending registry line / that a token exists.
while IFS= read -r rc; do
  [ -f "$rc" ] || continue
  # A non-default registry or an inline _authToken is worth a manual look.
  if grep -Eqs 'registry *=' "$rc" 2>/dev/null &&
    ! grep -Eqs 'registry *= *https://registry\.npmjs\.org/?' "$rc"; then
    report "[!] Non-default registry configured in $rc (confirm you set it):"
    grep -Ens 'registry *=' "$rc" | while IFS= read -r l; do report "      $l"; done
  fi
  if grep -Eqs '_authToken|_auth *=|_password' "$rc" 2>/dev/null; then
    report "[!] $rc contains an inline npm credential — rotate from a clean device."
    report "      (token value intentionally not copied to evidence)"
  fi
done < <({
  printf '%s\n' "$HOME/.npmrc"
  find "$ROOT" -maxdepth 4 "${SKIP_OUT[@]}" -name '.npmrc' -type f -print 2>/dev/null
} | sort -u)
report ""

# -----------------------------------------------------------------------------
# 3. Affected packages in GLOBAL / nvm node_modules (outside the $HOME scan)
# -----------------------------------------------------------------------------
report "=== Global / nvm node_modules ==="
GLOBAL_ROOTS=()
if [ "$HAVE_NPM" = "1" ]; then
  g="$(npm root -g 2>/dev/null)"
  [ -n "$g" ] && GLOBAL_ROOTS+=("$g")
  p="$(npm config get prefix 2>/dev/null)"
  [ -n "$p" ] && GLOBAL_ROOTS+=("$p/lib/node_modules" "$p/node_modules")
else
  report "[i] npm not on PATH; using well-known global prefixes only."
fi
GLOBAL_ROOTS+=(/usr/lib/node_modules /usr/local/lib/node_modules "$HOME/.npm-global/lib/node_modules")
# De-dup and scan. Use process substitution (not a pipe) so report()'s severity
# counters increment in THIS shell, not a lost subshell.
while IFS= read -r groot; do
  [ -d "$groot" ] || continue
  report "[i] Global node_modules root: $groot"
  for pkg in "${AFFECTED_PKGS[@]}"; do
    while IFS= read -r d; do
      report "[!] Affected package installed globally: $pkg -> $d"
    done < <(find "$groot" -maxdepth 3 "${SKIP_OUT[@]}" -type d -path "*/$pkg" -print 2>/dev/null)
  done
done < <(printf '%s\n' "${GLOBAL_ROOTS[@]}" | sort -u)
report ""

# -----------------------------------------------------------------------------
CRIT_F=$CRIT
WARN_F=$WARN
report "=== DONE ==="
report ""
report "Findings: ${CRIT_F} critical [!!], ${WARN_F} review [!]"
if [ "${CRIT_F:-0}" -gt 0 ]; then
  report "RESULT: COMPROMISE INDICATORS — treat this machine as compromised. Clean FIRST."
  exit 2
elif [ "${WARN_F:-0}" -gt 0 ]; then
  report "RESULT: SUSPICIOUS npm artifacts need manual review."
  exit 1
else
  report "RESULT: no suspicious npm supply-chain markers found (not a guarantee)."
  exit 0
fi
