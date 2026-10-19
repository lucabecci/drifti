#!/usr/bin/env bash
# Real Drifti CLI transcripts for Remotion / web (Linux host or CI runner).
set -eu

OUT="${1:-demo-captures}"
VER="${DRIFTI_VERSION:-0.1.0}"
USE_RELEASE="${USE_RELEASE_BINARY:-1}"

mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ "$USE_RELEASE" == "1" ]]; then
  cd "$WORK"
  curl -fsSL -O "https://github.com/lucabecci/drifti/releases/download/v${VER}/drifti-${VER}-x86_64-unknown-linux-gnu.tar.gz"
  tar -xzf "drifti-${VER}-x86_64-unknown-linux-gnu.tar.gz"
  DRIFTI="$WORK/drifti-${VER}-x86_64-unknown-linux-gnu/drifti"
else
  DRIFTI="${DRIFTI_BIN:-drifti}"
fi
chmod +x "$DRIFTI"

mkdir -p "$WORK/demo-repo"
cd "$WORK/demo-repo"
cat > mini-task.sh <<'EOF'
#!/bin/sh
set -eu
cat /etc/hosts >/dev/null
touch ./demo-touched.txt
cat ./demo-touched.txt
EOF
chmod +x mini-task.sh

log() {
  local id="$1"
  shift
  local f="$OUT/${id}.transcript"
  {
    printf '$ %s\n' "$*"
    set +e
    "$@"
    ec=$?
    set -e
    printf '\n[exit %s]\n' "$ec"
  } >"$f" 2>&1
  cp "$f" "$OUT/${id}.txt"
}

log_json() {
  local id="$1"
  local bin="$2"
  shift 2
  log "${id}-text" "$bin" --format text --color never "$@"
  log "${id}-json" "$bin" --format json --color never "$@"
}

log 01-help "$DRIFTI" --help
log_json 02-init "$DRIFTI" init
log_json 03-doctor "$DRIFTI" doctor
log_json 04-observe-true "$DRIFTI" observe -- /bin/true
log_json 05-observe-mini "$DRIFTI" observe -- ./mini-task.sh
log_json 06-learn "$DRIFTI" learn
log_json 07-generate "$DRIFTI" generate

if [[ -f drifti.yaml ]]; then
  log_json 08-verify-mini "$DRIFTI" verify -- ./mini-task.sh
else
  printf 'skipped: no drifti.yaml after generate\n' >"$OUT/08-verify-mini.skipped"
fi

{
  echo "Drifti v${VER} demo captures"
  echo "Host: $(uname -a)"
  echo "UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Binary: release tarball (USE_RELEASE_BINARY=${USE_RELEASE})"
  echo "Purpose: Remotion + web evidence (real CLI, not mock)."
} >"$OUT/README.txt"
