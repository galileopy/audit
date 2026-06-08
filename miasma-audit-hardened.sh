#!/usr/bin/env bash
#
# Miasma / Shai-Hulud read-only triage audit (hardened)
# ----------------------------------------------------
# Detection only. This script NEVER edits, removes, or rotates anything.
# If anything is flagged: clean the machine FIRST, rotate from a DIFFERENT
# trusted device SECOND. Do not revoke tokens from this machine.
#
# Covers the local, on-host portion of the checklist. Steps that live
# server-side (GitHub security log, npm publish history, Actions runners,
# OIDC trust) cannot be audited from here and are listed at the end.

# NOTE: deliberately NOT using `set -e`. A best-effort audit must not abort
# the moment `find` hits an unreadable directory (the normal case under $HOME).
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
miasma-audit-hardened.sh — read-only Miasma / Shai-Hulud on-host triage audit

USAGE:
  miasma-audit-hardened.sh [OPTIONS] [ROOT]
  miasma-audit-hardened.sh -h | --help

ARGS:
  ROOT                Directory tree to scan (default: \$HOME)

OPTIONS:
  --copy-evidence     Same as COPY_EVIDENCE=1 (preserve flagged files)
  --offline           Same as MIASMA_OFFLINE=1 (skip registry lookup)
  -h, --help          Show this help

ENV (flags above take precedence):
  COPY_EVIDENCE=1     Preserve copies of flagged files (may contain secrets/payloads)
  MIASMA_OFFLINE=1    Skip the npm-registry publish-date lookup (no outbound network)
  MIASMA_OUT_DIR=DIR  Write the audit folder here (default: next to this script)

EXIT CODES:
  2  [!!] confirmed indicator (bad version / worm marker) — assume compromised
  1  [!]  suspicious artifact — needs manual review
  0  clean of the on-host indicators this checks (not a guarantee)

Detection only: never edits, removes, or rotates anything.
EOF
}
COPY_EVIDENCE="${COPY_EVIDENCE:-0}"
MIASMA_OFFLINE="${MIASMA_OFFLINE:-0}"
ROOT=""
while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help)       usage; exit 0 ;;
    --copy-evidence) COPY_EVIDENCE=1 ;;
    --offline)       MIASMA_OFFLINE=1 ;;
    --)              shift; [ $# -gt 0 ] && ROOT="$1"; break ;;
    -*)              echo "unknown option: $1" >&2; usage; exit 64 ;;
    *)               if [ -z "$ROOT" ]; then ROOT="$1"; else echo "unexpected arg: $1" >&2; exit 64; fi ;;
  esac
  shift
done
ROOT="${ROOT:-$HOME}"

OUTBASE="${MIASMA_OUT_DIR:-$SCRIPT_DIR}"
OUT="$OUTBASE/miasma-shaihulud-audit-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT/evidence"

echo "Audit output: $OUT"
echo "Scanning under: $ROOT"
echo "(read-only: this script does not modify, remove, or rotate anything)"
echo "(publish-date check queries the npm registry; set MIASMA_OFFLINE=1 to skip)"
echo "(evidence copying is opt-in: set COPY_EVIDENCE=1 to preserve flagged files)"
echo

# --- Indicators of compromise -------------------------------------------------
# Package scopes/names known-affected across the Miasma waves (June 2026).
AFFECTED_PKGS=(
  "@redhat-cloud-services"   # scope, June 1 wave (32 pkgs / 96 versions)
  "@vapi-ai/server-sdk"      # June 3-4 Phantom Gyp wave
  "ai-sdk-ollama"
  "autotel" "awaitly" "executable-stories" "node-env-resolver"
  "wrangler-deploy" "mountly"
)

# Exact known-bad versions (extend as advisories update).
declare -A BAD_VERSIONS=(
  ["@vapi-ai/server-sdk"]="0.11.1 0.11.2 1.2.1 1.2.2"
  ["ai-sdk-ollama"]=">3.8.4"   # last clean is 3.8.4; anything newer is suspect
)

# On-disk marker strings left by the worm.
MARKERS='Miasma: The Spreading Blight|Shai-Hulud|api\.anthropic\.com/v1/api|__FAKE_PLATFORM__|TESTING_TAR_FAKE_PLATFORM|SKIP_DOMAIN|bypass_2fa'

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

# Tool availability — a missing tool yields an explicit [i] skip, never a
# silent pass.
have() { command -v "$1" >/dev/null 2>&1; }
HAVE_JQ=0;   have jq   && HAVE_JQ=1
HAVE_NPM=0;  have npm  && HAVE_NPM=1
HAVE_GIT=0;  have git  && HAVE_GIT=1
HAVE_STAT=0; have stat && HAVE_STAT=1

# Reusable prune so no find re-ingests a previous (or current) audit output dir,
# matched by NAME so it works wherever MIASMA_OUT_DIR points. Splice in right
# after the root: find "$ROOT" "${SKIP_OUT[@]}" ...
SKIP_OUT=(-type d \( -name 'miasma-shaihulud-audit-*' -o -name 'miasma-persistence-*' -o -name 'miasma-npm-supplychain-*' \) -prune -o)

# resolved_versions <dir> <pkg>: print the CONCRETE version(s) of $pkg that
# $dir actually resolves to. Authoritative via the lockfile; package.json only
# contributes when the dependency is pinned to an exact version (not a range).
resolved_versions() {
  local dir="$1" pkg="$2"
  [ "$HAVE_JQ" = "1" ] || return 0
  if [ -f "$dir/package-lock.json" ]; then
    jq -r --arg p "$pkg" '
      (.packages // {}) | to_entries[]
      | select((.key == "node_modules/" + $p)
               or (.key | endswith("/node_modules/" + $p)))
      | .value.version // empty' "$dir/package-lock.json" 2>/dev/null
  fi
  if [ -f "$dir/package.json" ]; then
    jq -r --arg p "$pkg" '
      [(.dependencies // {}), (.devDependencies // {}),
       (.optionalDependencies // {}), (.peerDependencies // {})]
      | map(.[$p] // empty)[]
      | select(type == "string" and test("^[0-9]+\\.[0-9]+\\.[0-9]"))
      ' "$dir/package.json" 2>/dev/null
  fi
}

# affected_resolved <dir>: print "name<TAB>version" for every affected package
# (including concrete members of an affected scope) resolved in $dir's lockfile.
affected_resolved() {
  local dir="$1"
  [ "$HAVE_JQ" = "1" ] && [ -f "$dir/package-lock.json" ] || return 0
  jq -r '
    (.packages // {}) | to_entries[]
    | select(.value.version != null)
    | { n: (.key | sub("^.*node_modules/"; "")), v: .value.version }
    | select(.n | test("^(@redhat-cloud-services/|@vapi-ai/server-sdk$|ai-sdk-ollama$|autotel$|awaitly$|executable-stories$|node-env-resolver$|wrangler-deploy$|mountly$)"))
    | "\(.n)\t\(.v)"' "$dir/package-lock.json" 2>/dev/null | sort -u
}

report "=== Miasma / Shai-Hulud defensive audit (read-only) ==="
report "Started: $(date -Is)"
report "Root: $ROOT"
miss=""
[ "$HAVE_JQ" = "1" ]   || miss="$miss jq"
[ "$HAVE_NPM" = "1" ]  || miss="$miss npm"
[ "$HAVE_GIT" = "1" ]  || miss="$miss git"
[ "$HAVE_STAT" = "1" ] || miss="$miss stat"
[ -n "$miss" ] && report "[i] Missing tools (related checks downgraded to manual):$miss"
report ""

# -----------------------------------------------------------------------------
# 1. Discover JS projects
# -----------------------------------------------------------------------------
PROJECTS=()
while IFS= read -r d; do PROJECTS+=("$d"); done < <(
  find "$ROOT" "${SKIP_OUT[@]}" \
    -type d \( -name node_modules -o -name .git -o -name dist -o -name build \) -prune -false \
    -o -type f \( -name package.json -o -name package-lock.json \
                  -o -name pnpm-lock.yaml -o -name yarn.lock \) \
    -printf '%h\n' 2>/dev/null | sort -u
)
report "Found ${#PROJECTS[@]} possible JS project(s)."
report ""

# -----------------------------------------------------------------------------
# 2. Manifest / lockfile references + version check
#    Presence is informational; a known-bad VERSION is the real signal.
# -----------------------------------------------------------------------------
for dir in "${PROJECTS[@]+"${PROJECTS[@]}"}"; do
  [ -f "$dir/package.json" ] || continue
  manifest_files=()
  for mf in package.json package-lock.json pnpm-lock.yaml yarn.lock; do
    [ -f "$dir/$mf" ] && manifest_files+=("$dir/$mf")
  done
  [ ${#manifest_files[@]} -gt 0 ] || continue

  printed_header=0
  for pkg in "${AFFECTED_PKGS[@]}"; do
    # Match the bare package name (works for package.json keys AND lockfile v3
    # "node_modules/<pkg>" keys, because we don't anchor on a leading quote).
    if grep -RqsF -- "$pkg" "${manifest_files[@]}" 2>/dev/null; then
      [ $printed_header -eq 0 ] && { report "## Project: $dir"; printed_header=1; }
      report "  [i] References affected package: $pkg"
      grep -RsnF -- "$pkg" "${manifest_files[@]}" 2>/dev/null \
        | tee -a "$OUT/package-matches.txt" >/dev/null

      # Flag a known-bad version only if the package ACTUALLY resolves to it.
      if [[ -n "${BAD_VERSIONS[$pkg]:-}" ]]; then
        rvers=(); while IFS= read -r rv; do [ -n "$rv" ] && rvers+=("$rv"); done \
          < <(resolved_versions "$dir" "$pkg" | sort -u)
        for bad in ${BAD_VERSIONS[$pkg]}; do
          if [[ "$bad" == ">"* ]]; then
            ceil="${bad#>}"
            if [ ${#rvers[@]} -gt 0 ]; then
              for rv in "${rvers[@]}"; do
                report "  [i] $pkg resolves to $rv; clean ceiling is $ceil — confirm $rv <= $ceil."
              done
            else
              report "  [i] $pkg: clean ceiling is $ceil; confirm the resolved version is <= $ceil."
            fi
          else
            for rv in "${rvers[@]+"${rvers[@]}"}"; do
              [ "$rv" = "$bad" ] && report "  [!!] KNOWN-BAD VERSION resolved: $pkg@$bad in $dir"
            done
          fi
        done
        # If we couldn't resolve a concrete version, say so instead of guessing.
        if [ "$HAVE_JQ" != "1" ]; then
          report "  [i] jq absent: cannot confirm resolved version of $pkg — review manually."
        elif [ ${#rvers[@]} -eq 0 ] \
             && { [ -f "$dir/pnpm-lock.yaml" ] || [ -f "$dir/yarn.lock" ]; } \
             && [ ! -f "$dir/package-lock.json" ]; then
          report "  [i] $pkg present but version unresolved (pnpm/yarn lockfile) — review manually."
        fi
      fi
    fi
  done
  [ $printed_header -eq 1 ] && report ""
done
report ""

# -----------------------------------------------------------------------------
# 2b. Authoritative installed-tree check via `npm ls`  (named in the checklist)
#     Read-only: `npm ls` / `npm view` never run package lifecycle scripts.
# -----------------------------------------------------------------------------
report "=== npm ls (authoritative installed-tree check) ==="
NPM_TARGETS=("@redhat-cloud-services" "@vapi-ai/server-sdk" "ai-sdk-ollama")
if command -v npm >/dev/null 2>&1; then
  for dir in "${PROJECTS[@]+"${PROJECTS[@]}"}"; do
    [ -f "$dir/package.json" ] || continue
    for pkg in "${NPM_TARGETS[@]}"; do
      ls_out="$( (cd "$dir" && npm ls "$pkg" --all 2>/dev/null) )"
      if printf '%s' "$ls_out" | grep -qF -- "$pkg@"; then
        report "[!] npm ls found $pkg in $dir:"
        while IFS= read -r l; do report "      $l"; done \
          < <(printf '%s\n' "$ls_out" | grep -F -- "$pkg@")
        printf '%s\n' "$ls_out" >> "$OUT/npm-ls-matches.txt"
      fi
    done
  done
else
  report "[i] npm not on PATH; skipped. Run 'npm ls <pkg>' manually per the checklist."
fi
report ""

# -----------------------------------------------------------------------------
# 2c. Publish-date correlation: versions PUBLISHED Jun 1 or Jun 3-4 (the waves).
#     Lockfiles carry no dates, so this asks the registry. Needs network;
#     set MIASMA_OFFLINE=1 to skip. A risk-window version that ALSO appears in
#     your manifests escalates to [!!].
# -----------------------------------------------------------------------------
report "=== Publish-date correlation (registry; Jun 1 / Jun 3-4 windows) ==="
# Only packages your lockfile ACTUALLY resolves are checked, and a [!!] requires
# that the resolved package@version was itself published in the risk window.
# We never treat a bare scope (e.g. @redhat-cloud-services) as a package.
declare -A NPMVIEW=()
if [ "${MIASMA_OFFLINE:-0}" = "1" ]; then
  report "[i] MIASMA_OFFLINE=1 set; skipped registry publish-date lookup."
elif [ "$HAVE_NPM" != "1" ]; then
  report "[i] npm not on PATH; cannot query registry publish dates. Check manually."
elif [ "$HAVE_JQ" != "1" ]; then
  report "[i] jq absent: cannot resolve exact versions for date correlation. Check manually."
else
  any_resolved=0
  for dir in "${PROJECTS[@]+"${PROJECTS[@]}"}"; do
    while IFS=$'\t' read -r name ver; do
      [ -n "$name" ] && [ -n "$ver" ] || continue
      any_resolved=1
      times="${NPMVIEW[$name]:-}"
      if [ -z "$times" ]; then
        times="$(npm view "$name" time --json 2>/dev/null)"
        NPMVIEW[$name]="${times:-_none_}"
      fi
      [ "$times" = "_none_" ] && continue
      pub="$(printf '%s' "$times" | jq -r --arg v "$ver" '.[$v] // empty' 2>/dev/null)"
      case "$pub" in
        2026-06-01*|2026-06-03*|2026-06-04*)
          report "[!!] $name@$ver (resolved in $dir) was PUBLISHED $pub — risk window" ;;
      esac
    done < <(affected_resolved "$dir")
  done
  [ "$any_resolved" = "0" ] && report "[i] No affected package resolves in any project lockfile."
fi
report ""

# -----------------------------------------------------------------------------
# 3. Installed-implant scan INSIDE node_modules  (Phantom Gyp / loader)
#    This is where the real payload lives, so node_modules is NOT pruned here.
# -----------------------------------------------------------------------------
report "=== Installed-package implant scan (node_modules) ==="
# 3a. binding.gyp inside installed packages. Native modules ship these
#     legitimately, so a generic hit is only [i]. Escalate when it sits inside
#     an affected package or next to a worm marker ([!!]), or is suspiciously
#     tiny (~157B is the dropper's tell -> [!]).
while IFS= read -r f; do
  sz=$(stat -c '%s' "$f" 2>/dev/null || echo 0)
  pkgdir=$(dirname "$f")
  reason=""; sev="i"
  for pkg in "${AFFECTED_PKGS[@]}"; do
    case "$f" in */node_modules/"$pkg"/*) reason="inside affected package $pkg"; sev="!!" ;; esac
  done
  if [ "$sev" = "i" ] && grep -RIEqs "$MARKERS" "$pkgdir" 2>/dev/null; then
    reason="worm marker in same package dir"; sev="!!"
  fi
  if [ "$sev" = "i" ] && [ "$sz" -gt 0 ] 2>/dev/null && [ "$sz" -le 200 ] 2>/dev/null; then
    reason="suspiciously tiny (~157B dropper tell)"; sev="!"
  fi
  case "$sev" in
    "!!") report "[!!] binding.gyp ($reason, ${sz}B): $f"; copy_evidence "$f" ;;
    "!")  report "[!] binding.gyp ($reason, ${sz}B): $f"; copy_evidence "$f" ;;
    *)    report "[i] binding.gyp in node_modules (native build, ${sz}B): $f" ;;
  esac
done < <(find "$ROOT" "${SKIP_OUT[@]}" -path '*/node_modules/*/binding.gyp' -type f -print 2>/dev/null)

# 3b. Oversized index.js at an installed package root (loader is ~4.5 MB).
while IFS= read -r f; do
  sz=$(stat -c '%s' "$f" 2>/dev/null || echo 0)
  report "[!] Oversized index.js in installed package (${sz}B): $f"
  copy_evidence "$f"
done < <(find "$ROOT" "${SKIP_OUT[@]}" -path '*/node_modules/*/index.js' -type f -size +1000000c -print 2>/dev/null)

# 3c. Known-affected packages actually present under node_modules.
for pkg in "${AFFECTED_PKGS[@]}"; do
  while IFS= read -r d; do
    report "[!] Affected package installed on disk: $pkg -> $d"
  done < <(find "$ROOT" "${SKIP_OUT[@]}" -type d -path "*/node_modules/$pkg" -print 2>/dev/null)
done
report ""

# -----------------------------------------------------------------------------
# 4. On-disk worm marker strings (incl. inside node_modules)
# -----------------------------------------------------------------------------
report "=== Worm marker-string scan ==="
while IFS= read -r m; do
  report "[!!] Marker string match: $m"
  echo "$m" >> "$OUT/marker-matches.txt"
done < <(grep -rIlE "$MARKERS" "$ROOT" \
           --exclude-dir='miasma-shaihulud-audit-*' \
           --exclude-dir='miasma-persistence-*' \
           --exclude-dir='miasma-npm-supplychain-*' \
           --include='*.js' --include='*.mjs' --include='*.cjs' \
           --include='*.json' --include='*.gyp' 2>/dev/null)
report ""

# -----------------------------------------------------------------------------
# 5. Bun runtime staged in temp + kitty daemon path (high-signal IOCs)
# -----------------------------------------------------------------------------
report "=== Staged Bun runtime / daemon path ==="
for tmp in "${TMPDIR:-/tmp}" /tmp /var/tmp; do
  [ -d "$tmp" ] || continue
  while IFS= read -r f; do
    report "[!] Possible staged Bun runtime: $f"
    copy_evidence "$f"
  done < <(find "$tmp" -maxdepth 2 "${SKIP_OUT[@]}" -type f -name 'bun*' -print 2>/dev/null)
  while IFS= read -r f; do
    report "[!] Suspicious kitty daemon path: $f"
  done < <(find "$tmp" -maxdepth 2 "${SKIP_OUT[@]}" -name 'kitty-*' -print 2>/dev/null)
done
report ""

# -----------------------------------------------------------------------------
# 6. Claude config & settings: hooks (esp. SessionStart) and MCP servers.
#    Covers user-global, per-project, *.local variants, ~/.claude.json, project
#    .mcp.json, and enterprise managed settings. Tiered: a worm marker -> [!!];
#    a hook/MCP command that fetches or executes -> [!]; a hook/MCP merely
#    configured -> [i]. These files routinely hold SECRETS, so they are copied
#    only with COPY_EVIDENCE=1 and never for an [i].
# -----------------------------------------------------------------------------
report "=== Claude config / settings hook check ==="
# Hook event names + MCP server config: presence alone is informational.
CLAUDE_PRESENT_RE='"hooks"|"SessionStart"|"PreToolUse"|"PostToolUse"|"UserPromptSubmit"|"Stop"|"SubagentStop"|"Notification"|"PreCompact"|"mcpServers"'
# A hook/MCP command that fetches or executes is the real tell.
CLAUDE_DROPPER_RE='curl |wget |/dev/tcp/|base64 -d|base64 --decode|node -e|node --eval|bun |setup\.mjs|setup\.js'
CLAUDE_FILES=(
  "$HOME/.claude.json"
  "$HOME/.claude/settings.json"
  "$HOME/.claude/settings.local.json"
  /etc/claude-code/managed-settings.json
)
while IFS= read -r f; do CLAUDE_FILES+=("$f"); done < <(
  find "$ROOT" "${SKIP_OUT[@]}" \
    \( -path "*/.claude/settings.json" -o -path "*/.claude/settings.local.json" \
       -o -path "*/.mcp.json" \) -type f -print 2>/dev/null)
declare -A seen_claude=()
for f in "${CLAUDE_FILES[@]}"; do
  [ -f "$f" ] || continue
  [ -n "${seen_claude[$f]:-}" ] && continue
  seen_claude[$f]=1
  if grep -EqsI "$MARKERS" "$f" 2>/dev/null; then
    report "[!!] Worm marker in Claude config (may contain SECRETS): $f"
    copy_evidence "$f"
    grep -EnsI "$MARKERS" "$f" 2>/dev/null | tee -a "$OUT/claude-hook-matches.txt" >/dev/null
  elif grep -EqsI "$CLAUDE_DROPPER_RE" "$f" 2>/dev/null; then
    report "[!] Claude hook/MCP command fetches or executes — review (may contain SECRETS): $f"
    copy_evidence "$f"
    grep -EnsI "$CLAUDE_DROPPER_RE|\"command\"" "$f" 2>/dev/null | tee -a "$OUT/claude-hook-matches.txt" >/dev/null
  elif grep -EqsI "$CLAUDE_PRESENT_RE" "$f" 2>/dev/null; then
    report "[i] Hooks/MCP configured here — confirm you added them: $f"
    grep -EnsI "$CLAUDE_PRESENT_RE" "$f" 2>/dev/null | tee -a "$OUT/claude-hook-matches.txt" >/dev/null
  fi
done
report ""

# -----------------------------------------------------------------------------
# 7. VS Code folderOpen tasks
# -----------------------------------------------------------------------------
report "=== VS Code folderOpen task check ==="
while IFS= read -r f; do
  if grep -Eqs '"folderOpen"|"runOptions"|setup\.js|setup\.mjs|curl |wget ' "$f"; then
    report "[!] Review VS Code task file: $f"
    copy_evidence "$f"
    grep -Ens '"folderOpen"|"runOptions"|"runOn"|setup\.js|setup\.mjs|curl |wget ' "$f" \
      | tee -a "$OUT/vscode-task-matches.txt" >/dev/null
  fi
done < <(find "$ROOT" "${SKIP_OUT[@]}" -path "*/.vscode/tasks.json" -type f -print 2>/dev/null)
report ""

# -----------------------------------------------------------------------------
# 8. Suspicious persistence file names
# -----------------------------------------------------------------------------
report "=== Suspicious persistence file names ==="
while IFS= read -r f; do
  report "[!] File worth reviewing: $f"
  copy_evidence "$f"
done < <(find "$ROOT" "${SKIP_OUT[@]}" \
  -type d \( -name .git \) -prune -false \
  -o -type f \( -path "*/.github/setup.js" -o -path "*/.claude/setup.mjs" \) \
  -print 2>/dev/null)
report ""

# -----------------------------------------------------------------------------
# 9. GitHub Actions workflows (local view of the OIDC/runner attack surface)
# -----------------------------------------------------------------------------
report "=== GitHub Actions workflow review ==="
while IFS= read -r f; do
  if grep -Eqs 'self-hosted|id-token: *write|runs-on:.*self|preinstall|setup\.(js|mjs)|curl |wget |npm publish' "$f"; then
    report "[!] Review workflow (self-hosted runner / OIDC write / install hook): $f"
    copy_evidence "$f"
  fi
  # Recently-modified workflows during the risk window deserve a manual look.
  if [ -n "$(find "$f" -newermt '2026-05-29' ! -newermt '2026-06-06' 2>/dev/null)" ]; then
    report "[i] Workflow modified during risk window: $f"
  fi
done < <(find "$ROOT" "${SKIP_OUT[@]}" -path '*/.github/workflows/*' -type f \( -name '*.yml' -o -name '*.yaml' \) -print 2>/dev/null)
report ""

# -----------------------------------------------------------------------------
# 10. Local git indicators
# -----------------------------------------------------------------------------
report "=== Git indicator check ==="
if [ "$HAVE_GIT" != "1" ]; then
  report "[i] git not on PATH; skipped local git indicator check."
else
  while IFS= read -r gitdir; do
    repo="$(dirname "$gitdir")"
    tmplog="$(mktemp)"
    if git -C "$repo" log --all --since="2026-05-29" --until="2026-06-06" \
          --oneline --decorate --stat >"$tmplog" 2>/dev/null && [ -s "$tmplog" ]; then
      report "[i] Commits during risk window: $repo"
      cat "$tmplog" >> "$OUT/git-risk-window-commits.txt"
    fi
    rm -f "$tmplog"
    if git -C "$repo" grep -nE "Miasma|Shai-Hulud|SessionStart|folderOpen|setup\.(js|mjs)" \
          HEAD -- . >>"$OUT/git-suspicious-grep.txt" 2>/dev/null; then
      report "[!] Suspicious strings in git repo: $repo"
    fi
  done < <(find "$ROOT" "${SKIP_OUT[@]}" -type d -name .git -print 2>/dev/null)
fi
report ""

# -----------------------------------------------------------------------------
# Off-host steps this script CANNOT perform — do these manually
# -----------------------------------------------------------------------------
# Snapshot counts BEFORE the advisory text below (which itself mentions [!]/[!!]).
CRIT_F=$CRIT; WARN_F=$WARN
report "=== Off-host checks (cannot be done from this machine) ==="
report "  - GitHub security log: github.com/settings/security-log"
report "    (repos you didn't create, esp. described 'Miasma: The Spreading Blight')"
report "  - npm publish history / GitHub audit log: any version or commit you didn't make"
report "  - GitHub Actions self-hosted runners and workflows you didn't set up"
report "  - GitHub Actions OIDC trust relationships (the Red Hat attack vector)"
report ""

report "=== DONE ==="
report "Review: $OUT/report.txt"
report ""
report "If anything is marked [!] or [!!]:"
report "  1. Do NOT rotate or revoke anything from this machine."
report "  2. Preserve evidence, disconnect from the network."
report "  3. Clean from trusted media, then rotate from a DIFFERENT trusted device,"
report "     in order: npm tokens, GitHub PATs, SSH keys, then cloud (AWS/GCP/Azure),"
report "     Kubernetes, Vault."
report "  4. Re-run with COPY_EVIDENCE=1 to preserve flagged files for forensics"
report "     (those copies may themselves contain secrets or live payloads)."
report ""
report "Findings: ${CRIT_F} critical [!!], ${WARN_F} review [!]"
if [ "${CRIT_F:-0}" -gt 0 ]; then
  report "RESULT: COMPROMISE INDICATORS — treat this machine as compromised. Clean FIRST."
  exit 2
elif [ "${WARN_F:-0}" -gt 0 ]; then
  report "RESULT: SUSPICIOUS artifacts need manual review (no confirmed bad version/marker)."
  exit 1
else
  report "RESULT: clean of the on-host indicators this script checks (not a guarantee)."
  exit 0
fi
