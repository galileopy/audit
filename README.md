# Miasma / Shai-Hulud audit

Read-only triage scripts to check a machine for signs of the Miasma / Shai-Hulud
npm supply-chain compromise (June 2026 waves: `@redhat-cloud-services`,
`@vapi-ai/server-sdk`, `ai-sdk-ollama`, and the "Phantom Gyp" wave).

**Detection only.** Nothing here edits, removes, or rotates anything. If a scan
flags something, the order matters: **clean the machine first, rotate second,
from a different trusted device.** Cutting access while a backdoor is still live
can trigger retaliation (e.g. wiping `$HOME`).

## Scripts

| Script | What it checks |
|---|---|
| `run-all.sh` | Runs all three scans below, tees a combined log, exits with the worst result code |
| `miasma-audit-hardened.sh` | Affected packages/versions (lockfile-resolved), `npm ls`, registry publish-dates, node_modules implants, worm marker strings, Claude config & hooks (incl. `~/.claude.json`, `settings.local`, project `.mcp.json`, MCP servers, managed settings), VS Code tasks, GitHub workflows, local git history |
| `miasma-persistence-scan.sh` | Shell startup files, cron, systemd user units, git hooks |
| `miasma-npm-supplychain-scan.sh` | `package.json` lifecycle scripts, `~/.npmrc`, global / nvm `node_modules` |

The main script covers the on-host portion of the public checklist; the two
companions cover persistence and npm surface beyond it. Off-host steps the
scripts cannot perform (GitHub security log, npm publish history, Actions
runners, OIDC trust) are listed at the end of the main report.

## Usage

```bash
# run everything, scanning $HOME, summarise the worst result
./run-all.sh

# scan a specific tree
./run-all.sh ~/Documents/repos

# preserve copies of flagged files for forensics; stay fully offline
./run-all.sh --copy-evidence --offline ~/Documents/repos

# run a single scan
./miasma-audit-hardened.sh
./miasma-persistence-scan.sh --copy-evidence
./miasma-npm-supplychain-scan.sh ~/code

# help for any of them
./run-all.sh --help
```

Each scan writes a timestamped folder (and `run-all.sh` a combined `.log`) **next
to the scripts** by default. Reports are plain text:

```bash
grep -E '\[!!\]|\[!\]' miasma-shaihulud-audit-*/report.txt
```

## Run without cloning (curl | bash)

> [!WARNING]
> Piping a remote script straight into a shell is the **exact pattern this tool
> exists to detect**. Whatever the URL serves runs immediately, unreviewed, with
> your privileges — a tampered repo, a hijacked CDN, or a MITM all become code
> execution. On a machine you already suspect is compromised, prefer the
> **download → inspect → run** flow below.

**Safer: download, read, then run.**

```bash
curl -fsSLO https://raw.githubusercontent.com/galileopy/audit/main/miasma-audit-hardened.sh
less miasma-audit-hardened.sh        # eyeball it first
bash miasma-audit-hardened.sh --offline ~/code
```

**Convenience one-liners** (note: `bash`, not `sh` — these use bash features;
and pass flags/args after `-s --`):

```bash
# main on-host audit
curl -fsSL https://raw.githubusercontent.com/galileopy/audit/main/miasma-audit-hardened.sh | bash

# with flags / a scan root
curl -fsSL https://raw.githubusercontent.com/galileopy/audit/main/miasma-audit-hardened.sh | bash -s -- --offline --copy-evidence ~/code

# persistence scan
curl -fsSL https://raw.githubusercontent.com/galileopy/audit/main/miasma-persistence-scan.sh | bash

# npm supply-chain scan
curl -fsSL https://raw.githubusercontent.com/galileopy/audit/main/miasma-npm-supplychain-scan.sh | bash
```

When piped this way there is no script file on disk, so output is written under
the **current directory** by default (override with `MIASMA_OUT_DIR`).

`run-all.sh` **cannot** be piped — it runs the three sibling scripts by path, so
it needs them on disk. To use the runner, clone the repo:

```bash
git clone https://github.com/galileopy/audit.git && cd audit && ./run-all.sh
```

## Options & environment

| Flag | Equivalent env var | Effect |
|---|---|---|
| `--copy-evidence` | `COPY_EVIDENCE=1` | Preserve copies of flagged files (may contain secrets / live payloads) — off by default |
| `--offline` | `MIASMA_OFFLINE=1` | Skip the npm-registry publish-date lookup (no outbound network); main script only |
| `-h`, `--help` | — | Show help |
| — | `MIASMA_OUT_DIR=DIR` | Write output here instead of next to the scripts |

`--copy-evidence` is **opt-in** because the copies can contain credentials and
live payloads. Turn it on for a real incident (before you wipe); leave it off
for routine sweeps.

## Exit codes

| Code | Meaning |
|---|---|
| `2` | `[!!]` confirmed indicator (bad resolved version / worm marker) — assume compromised |
| `1` | `[!]` suspicious artifact — needs manual review |
| `0` | clean of the on-host indicators these scans check (not a guarantee) |

`run-all.sh` exits with the worst of the three.

## If something is flagged

1. **Do not** rotate or revoke anything from this machine.
2. Re-run with `--copy-evidence` to preserve evidence, then disconnect from the network.
3. Clean the machine (or wipe / reimage).
4. **Then** rotate, from a different trusted device, in order:
   npm tokens → GitHub PATs → SSH keys → cloud (AWS/GCP/Azure) → Kubernetes → Vault.
5. Do the off-host checks listed at the end of the main report.

## Requirements

Required: `bash` 4+, `find`, `grep`. Optional but recommended: `jq` (authoritative
version resolution), `npm` (`npm ls` + registry date check), `git` (history
check), `stat` (file sizes for the `binding.gyp` / `index.js` heuristics). A
missing tool degrades the relevant check to an explicit `[i] skipped` and is
listed at the top of the report — never a silent pass.
