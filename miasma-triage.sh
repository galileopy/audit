#!/usr/bin/env bash
#
# miasma-triage.sh — read-only deep dive over an EXISTING Miasma / Shai-Hulud
# audit report. It does NOT re-scan the tree; it re-reads only the handful of
# files the audit already flagged, so it is fast even when the original scan was
# slow. Point it at an audit output folder (or its parent).
#
# For each [!!] worm-marker hit it shows WHICH marker matched and the line; for a
# lockfile it maps the marker to the offending package@version + resolved URL;
# and it runs local exposure checks (was it installed? any auto-run vectors?).
#
# Detection only: never installs, executes, edits, or rotates anything.
# Portable across GNU/Linux and BSD/macOS.

set -uo pipefail

usage() {
  cat <<EOF
miasma-triage.sh — deep-dive an existing audit report (no re-scan)

USAGE:
  miasma-triage.sh REPORT          # an audit folder, its parent, or a report.txt
  miasma-triage.sh -h | --help

WHAT IT DOES (read-only):
  - summarises [!!]/[!]/[i] counts and the RESULT line
  - for each worm-marker [!!]: which marker, the matching line(s), and — for a
    lockfile — the offending package name / version / resolved URL
  - exposure per repo: node_modules present (installed?), custom git hooks,
    VS Code folderOpen tasks, and recent commits touching the file
  - echoes the other match-detail artifacts the scan wrote

Re-reads only flagged files, so it is fast. Needs the flagged files still on
disk to enrich them; otherwise it falls back to what the report recorded.
Optional: jq (lockfile -> package mapping), git (provenance).
EOF
}

# --- config: kept in sync with miasma-audit-hardened.sh ----------------------
# ERE for grep (matches the audit's worm markers).
MARKERS='Miasma: The Spreading Blight|Shai-Hulud|api\.anthropic\.com/v1/api|SKIP_DOMAIN|bypass_2fa'
# Same markers as a jq test() regex (single backslashes; passed via --arg).
MARKERS_JQ='Shai-Hulud|Miasma|bypass_2fa|SKIP_DOMAIN|api\.anthropic\.com/v1/api'

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n=== %s ===\n' "$1"; }

# Real finding lines start with the bracket token (optionally indented); this
# excludes advisory prose like "If anything is marked [!]..." or the audit's own
# "Findings: N critical [!!]" tally.
CRIT_RE='^[[:space:]]*\[!!\]'
WARN_RE='^[[:space:]]*\[!\]'
INFO_RE='^[[:space:]]*\[i\]'

# Count of flagged repos that show an execution/auto-run vector (set in
# exposure_for, read for the closing verdict).
EXPOSED=0

# locate_report <path>: echo the report.txt to read (accepts a report.txt, an
# audit folder, or a parent of one — newest wins).
locate_report() {
  local p="$1"
  case "$p" in */report.txt) [ -f "$p" ] && { printf '%s\n' "$p"; return 0; } ;; esac
  [ -f "$p/report.txt" ] && { printf '%s\n' "$p/report.txt"; return 0; }
  local newest
  newest="$(find "$p" -maxdepth 3 -type f -name report.txt 2>/dev/null | sort | tail -n1)"
  [ -n "$newest" ] && { printf '%s\n' "$newest"; return 0; }
  return 1
}

# find_repo_root <file>: best-effort repo root for a flagged file. Anything under
# node_modules belongs to the package root above it; otherwise walk up to the
# nearest dir holding .git or package.json.
find_repo_root() {
  local f="$1" d
  case "$f" in */node_modules/*) printf '%s\n' "${f%%/node_modules/*}"; return 0 ;; esac
  d="$(dirname "$f")"
  while [ "$d" != "/" ] && [ "$d" != "." ] && [ -n "$d" ]; do
    if [ -d "$d/.git" ] || [ -f "$d/package.json" ]; then
      printf '%s\n' "$d"
      return 0
    fi
    d="$(dirname "$d")"
  done
  dirname "$f"
}

summarize() {
  local r="$1" crit warn info
  section "Summary"
  printf '  Report: %s\n' "$r"
  grep -E '^(Root|Started):' "$r" 2>/dev/null | sed 's/^/  /'
  crit="$(grep -cE "$CRIT_RE" "$r")"
  warn="$(grep -cE "$WARN_RE" "$r")"
  info="$(grep -cE "$INFO_RE" "$r")"
  printf '  [!!] confirmed: %s    [!] review: %s    [i] info: %s\n' "$crit" "$warn" "$info"
  grep -E '^RESULT:' "$r" 2>/dev/null | sed 's/^/  /'
}

list_findings() {
  local r="$1" out
  section "All [!!] and [!] findings"
  out="$(grep -nE "$CRIT_RE|$WARN_RE" "$r")"
  if [ -n "$out" ]; then printf '%s\n' "$out" | sed 's/^/  /'; else echo "  (none)"; fi
}

# marker_files <report.txt>: the files the worm-marker scan flagged.
marker_files() {
  grep -E '\[!!\] Marker string match: ' "$1" 2>/dev/null | sed 's/.*Marker string match: //'
}

# map_lockfile_packages <package-lock.json>: print "name  version  resolved" for
# every package entry whose key/value carries a marker.
map_lockfile_packages() {
  jq -r --arg re "$MARKERS_JQ" '
    .packages // {} | to_entries[]
    | select((.key + " " + (.value | tostring)) | test($re))
    | "      \(.key | sub("^.*node_modules/"; ""))\t\(.value.version // "?")\t\(.value.resolved // "")"' \
    "$1" 2>/dev/null
}

exposure_for() {
  local f="$1" repo hooks exposed=0
  repo="$(find_repo_root "$f")"
  printf '    repo root: %s\n' "$repo"
  if [ -n "$(find "$repo" -type d -name node_modules -prune -print 2>/dev/null | head -n1)" ]; then
    printf '    [!] node_modules present under repo — packages WERE installed; review the §3 implant scan / npm ls section\n'
    exposed=1
  else
    printf '    [ok] no node_modules under repo — not installed (a lockfile is inert data; no code runs from it alone)\n'
  fi
  if [ -d "$repo/.git/hooks" ]; then
    hooks="$(find "$repo/.git/hooks" -type f ! -name '*.sample' 2>/dev/null)"
    [ -n "$hooks" ] && {
      printf '    [!] custom git hooks (run on git operations):\n%s\n' "$(printf '%s\n' "$hooks" | sed 's/^/        /')"
      exposed=1
    }
  fi
  if [ -f "$repo/.vscode/tasks.json" ] && grep -qs 'folderOpen' "$repo/.vscode/tasks.json"; then
    printf '    [!] .vscode/tasks.json has a folderOpen task — auto-runs when the folder is opened in VS Code\n'
    exposed=1
  fi
  [ "$exposed" = "1" ] && EXPOSED=$((EXPOSED + 1))
  if [ -d "$repo/.git" ] && have git; then
    printf '    recent commits touching this file:\n'
    git -C "$repo" log --oneline -5 -- "$f" 2>/dev/null | sed 's/^/        /'
  fi
}

deep_dive_file() {
  local f="$1"
  printf '\n— %s\n' "$f"
  if [ ! -e "$f" ]; then
    echo "    (file no longer on this machine — cannot enrich; see package-matches.txt below)"
    return 0
  fi
  echo "    markers matched:"
  LC_ALL=C grep -oIE "$MARKERS" "$f" 2>/dev/null | sort -u | sed 's/^/      - /'
  echo "    matching line(s) (capped 10 x 200c):"
  LC_ALL=C grep -nIE "$MARKERS" "$f" 2>/dev/null | head -n 10 | cut -c1-200 | sed 's/^/      /'
  case "$(basename "$f")" in
  package-lock.json | npm-shrinkwrap.json)
    if have jq; then
      echo "    offending package(s)  name / version / resolved:"
      map_lockfile_packages "$f"
    else
      echo "    (install jq to map the marker to the offending package)"
    fi
    ;;
  yarn.lock | pnpm-lock.yaml)
    echo "    (non-JSON lockfile — the package block is in the matching line(s) above)"
    ;;
  esac
  exposure_for "$f"
}

show_other_artifacts() {
  local d="$1" af
  for af in package-matches.txt npm-ls-matches.txt claude-hook-matches.txt \
    vscode-task-matches.txt git-suspicious-grep.txt git-risk-window-commits.txt; do
    if [ -s "$d/$af" ]; then
      section "Artifact: $af (first 100 lines)"
      head -n 100 "$d/$af" | sed 's/^/  /'
    fi
  done
}

closing_notes() {
  section "How to read this"
  cat <<'EOF'
  - Lockfile-only marker + no node_modules under the repo + no custom git hooks
    + no folderOpen task  =>  the marker rode in as DATA in a pinned dependency
    you never installed. No code executed; no credential rotation needed.
  - If a flagged repo DOES have node_modules (or §3/§2b flagged something), the
    package may have been installed — treat per the audit's remediation steps.
  - Do NOT run npm/yarn/pnpm install in a flagged repo. Quarantine or delete it,
    and report the offending package@version upstream.
EOF
}

main() {
  local target="${1:-}"
  case "$target" in
  "" ) usage; exit 64 ;;
  -h | --help) usage; exit 0 ;;
  esac
  local report dir
  report="$(locate_report "$target")" || {
    echo "No report.txt found at/under: $target" >&2
    exit 66
  }
  dir="$(dirname "$report")"

  summarize "$report"
  list_findings "$report"

  section "Worm-marker deep dive"
  local any=0 f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    any=1
    deep_dive_file "$f"
  done < <(marker_files "$report")
  [ "$any" = "0" ] && echo "  (no [!!] worm-marker matches in this report)"

  show_other_artifacts "$dir"
  print_verdict "$any"
  closing_notes
}

# print_verdict <had-marker-hits>: one-line bottom line from the exposure tally.
print_verdict() {
  section "Verdict"
  if [ "$1" = "0" ]; then
    echo "  No worm-marker [!!] in this report — nothing to deep-dive here."
  elif [ "$EXPOSED" = "0" ]; then
    echo "  No execution vectors found next to any marker (no node_modules, no custom"
    echo "  git hooks, no folderOpen task). Exposure looks DATA-ONLY — the marker rode"
    echo "  in via a pinned dependency that was never installed or run."
  else
    echo "  $EXPOSED flagged repo(s) show an install/auto-run vector — possible EXECUTION."
    echo "  Investigate those per the audit's remediation steps before assuming safe."
  fi
}

main "$@"
