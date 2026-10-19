#!/usr/bin/env bash
# Capture real Drifti CLI transcripts on Linux (KAN-35-style, sanitized for media).
set -eu

OUT="${1:-demo-captures}"
VER="${DRIFTI_VERSION:-0.1.0}"
mkdir -p "$OUT"
cd "$(mktemp -d)"
WORK="$PWD"

log() {
  local id="$1"
  shift
  local logfile="$OUT/${id}.transcript"
  {
    printf '$ %s\n' "$*"
    set +e
    "$@"
    ec=$?
    set -e
    printf '\n[exit %s]\n' "$ec"
  } >"$logfile" 2>&1
  cp "$logfile" "$OUT/${id}.txt"
}

curl -fsSL -O "https://github.com/lucabecci/drifti/releases/download/v${VER}/drifti-${VER}-x86_64-unknown-linux-gnu.tar.gz"
tar -xzf "drifti-${VER}-x86_64-unknown-linux-gnu.tar.gz"
DRIFTI="$PWD/drifti-${VER}-x86_64-unknown-linux-gnu/drifti"
chmod +x "$DRIFTI"

mkdir -p "$WORK/demo-repo"
cd "$WORK/demo-repo"

log "01-help" "$DRIFTI" --help
log "02-init" "$DRIFTI" init
log "03-doctor" "$DRIFTI" doctor
log "04-observe-true" "$DRIFTI" observe -- /bin/true
log "05-learn" "$DRIFTI" learn
log "06-generate" "$DRIFTI" generate

cat >"$OUT/README.txt" <<EOF
Real Drifti v${VER} transcripts from ubuntu-latest ($(date -u +%Y-%m-%dT%H:%M:%SZ)).
Host: GitHub Actions demo-capture workflow.
Repo cwd: disposable temp demo-repo (not the canonical Rust story yet).
Use in drifti-studio / Remotion as monospace text or re-record terminal styling.
EOF
