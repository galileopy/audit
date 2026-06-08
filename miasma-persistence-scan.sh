#!/usr/bin/env bash
#
# Miasma / Shai-Hulud persistence scan (companion to miasma-audit-hardened.sh)
# ---------------------------------------------------------------------------
# Detection only. NEVER edits, removes, or rotates anything.
# Covers persistence channels NOT in the original checklist:
#   - shell startup files (.bashrc / .zshrc / .profile / fish)
#   - user + system cron
#   - systemd user units
#   - git hooks (.git/hooks/*)
# Same convention as the main audit: clean the machine FIRST, then rotate from
# a DIFFERENT trusted device. Do not revoke tokens from this machine.

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
miasma-persistence-scan.sh — read-only Miasma / Shai-Hulud persistence scan

USAGE:
  miasma-persistence-scan.sh [OPTIONS] [ROOT]
  miasma-persistence-scan.sh -h | --help

Scans shell startup files, cron, systemd user units, and git hooks.

ARGS:
  ROOT                Directory tree to scan for git hooks (default: \$HOME)

OPTIONS:
  --copy-evidence     Same as COPY_EVIDENCE=1 (preserve flagged files)
  --offline           Accepted for wrapper compatibility (this script makes no network calls)
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
    -h|--help)       usage; exit 0 ;;
    --copy-evidence) COPY_EVIDENCE=1 ;;
    --offline)       : ;;  # accepted for wrapper compatibility; no network here
    --)              shift; [ $# -gt 0 ] && ROOT="$1"; break ;;
    -*)              echo "unknown option: $1" >&2; usage; exit 64 ;;
    *)               if [ -z "$ROOT" ]; then ROOT="$1"; else echo "unexpected arg: $1" >&2; exit 64; fi ;;
  esac
  shift
done
ROOT="${ROOT:-$HOME}"

OUTBASE="${MIASMA_OUT_DIR:-$SCRIPT_DIR}"
OUT="$OUTBASE/miasma-persistence-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT/evidence"

# Definitive worm markers (a hit here is [!!]); aligned with the main audit.
MARKERS='Miasma|Shai-Hulud|api\.anthropic\.com/v1/api|__FAKE_PLATFORM__|TESTING_TAR_FAKE_PLATFORM|SKIP_DOMAIN|bypass_2fa'
# Generic dropper commands a benign rc/hook rarely needs (a hit here is [!] review).
SUSPICIOUS='curl |wget |base64 -d|base64 --decode|node -e|node --eval|bun |eval "\$\(|/dev/tcp/|nc -e|SessionStart|setup\.(js|mjs)'

# Severity counters drive the exit code: [!!]=confirmed/critical, [!]=review.
CRIT=0; WARN=0
report() {
  case "$*" in
    *"[!!]"*) CRIT=$((CRIT+1)) ;;
    *"[!]"*)  WARN=$((WARN+1)) ;;
  esac
  printf '%s\n' "$*" | tee -a "$OUT/report.txt"
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
HAVE_CRONTAB=0; have crontab && HAVE_CRONTAB=1

# Reusable prune so the scan never re-ingests an audit output directory, matched
# by NAME so it works wherever MIASMA_OUT_DIR points.
SKIP_OUT=(-type d \( -name 'miasma-shaihulud-audit-*' -o -name 'miasma-persistence-*' -o -name 'miasma-npm-supplychain-*' \) -prune -o)

# scan_file <path> <label> [extra_regex]
#   worm marker -> [!!];  generic dropper command (or extra) -> [!].
scan_file() {
  local f="$1" label="$2" extra="${3:-}"
  [ -f "$f" ] || return 0
  if grep -EqsI "$MARKERS" "$f" 2>/dev/null; then
    report "[!!] $label: worm marker in $f"
    copy_evidence "$f"
    grep -EnsI "$MARKERS" "$f" 2>/dev/null | tee -a "$OUT/persistence-matches.txt" >/dev/null
  elif grep -EqsI "$SUSPICIOUS${extra:+|$extra}" "$f" 2>/dev/null; then
    report "[!] $label: suspicious content in $f (review)"
    copy_evidence "$f"
    grep -EnsI "$SUSPICIOUS${extra:+|$extra}" "$f" 2>/dev/null | tee -a "$OUT/persistence-matches.txt" >/dev/null
  fi
}

echo "Persistence audit output: $OUT"
echo "(read-only: this script does not modify, remove, or rotate anything)"
echo "(evidence copying is opt-in: set COPY_EVIDENCE=1 to preserve flagged files)"
echo
report "=== Miasma / Shai-Hulud persistence scan (read-only) ==="
report "Started: $(date '+%Y-%m-%dT%H:%M:%S%z')"
report "Root: $ROOT"
[ "$HAVE_CRONTAB" = "1" ] || report "[i] crontab not on PATH; user crontab not read (system cron still scanned)."
report ""

# -----------------------------------------------------------------------------
# 1. Shell startup files (the most common persistence channel)
# -----------------------------------------------------------------------------
report "=== Shell startup files ==="
for rc in \
  "$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.bash_login" "$HOME/.profile" \
  "$HOME/.zshrc" "$HOME/.zshenv" "$HOME/.zprofile" "$HOME/.zlogin" \
  "$HOME/.config/fish/config.fish" \
  /etc/profile /etc/bash.bashrc /etc/zsh/zshrc; do
  scan_file "$rc" "shell rc"
done
# Anything sourced from ~/.bashrc.d or ~/.profile.d style drop-in dirs.
while IFS= read -r f; do scan_file "$f" "shell rc drop-in"; done < <(
  find "$HOME"/.bashrc.d "$HOME"/.profile.d "$HOME"/.config/fish/conf.d \
    "${SKIP_OUT[@]}" -type f -print 2>/dev/null)
report ""

# -----------------------------------------------------------------------------
# 2. Cron (user + system)
# -----------------------------------------------------------------------------
report "=== Cron ==="
if [ "$HAVE_CRONTAB" = "1" ]; then
  cron_out="$(crontab -l 2>/dev/null)"
  if [ -n "$cron_out" ]; then
    if printf '%s' "$cron_out" | grep -EqsI "$MARKERS"; then
      report "[!!] User crontab contains a worm marker."
    elif printf '%s' "$cron_out" | grep -EqsI "$SUSPICIOUS"; then
      report "[!] User crontab contains suspicious entries (review)."
    else
      report "[i] User crontab present but no suspicious markers; review manually."
    fi
    [ "$COPY_EVIDENCE" = "1" ] && printf '%s\n' "$cron_out" > "$OUT/evidence/user-crontab.txt"
  fi
fi
while IFS= read -r f; do scan_file "$f" "cron"; done < <(
  find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly \
       /etc/cron.monthly /var/spool/cron "${SKIP_OUT[@]}" -type f -print 2>/dev/null)
scan_file /etc/crontab "cron"
report ""

# -----------------------------------------------------------------------------
# 3. systemd user units (persistence via --user services/timers)
# -----------------------------------------------------------------------------
report "=== systemd user units ==="
while IFS= read -r f; do
  # An ExecStart pointing at curl/node/bun or a temp path is the extra tell.
  scan_file "$f" "systemd user unit" 'ExecStart=.*(curl|wget|/tmp/|node |bun )'
done < <(find "$HOME/.config/systemd/user" "$HOME/.local/share/systemd/user" \
              "${SKIP_OUT[@]}" -type f \( -name '*.service' -o -name '*.timer' \) -print 2>/dev/null)
report ""

# -----------------------------------------------------------------------------
# 4. git hooks (.git/hooks/* — runs on commit/checkout/merge)
# -----------------------------------------------------------------------------
report "=== git hooks ==="
while IFS= read -r hook; do
  # Skip the inert .sample files git ships with.
  case "$hook" in *.sample) continue ;; esac
  [ -f "$hook" ] || continue
  scan_file "$hook" "git hook"
done < <(find "$ROOT" "${SKIP_OUT[@]}" -type d -name hooks -path '*/.git/hooks' \
              -exec find {} -type f \; 2>/dev/null)
report ""

# -----------------------------------------------------------------------------
CRIT_F=$CRIT; WARN_F=$WARN
report "=== DONE ==="
report ""
report "Findings: ${CRIT_F} critical [!!], ${WARN_F} review [!]"
if [ "${CRIT_F:-0}" -gt 0 ]; then
  report "RESULT: COMPROMISE INDICATORS — treat this machine as compromised. Clean FIRST."
  exit 2
elif [ "${WARN_F:-0}" -gt 0 ]; then
  report "RESULT: SUSPICIOUS persistence artifacts need manual review."
  exit 1
else
  report "RESULT: no suspicious persistence markers found (not a guarantee)."
  exit 0
fi
