#!/bin/sh
# Point this clone at the committed Conventional Commits hook and template.
set -eu

cd "$(dirname "$0")/.."

git rev-parse --git-dir >/dev/null

git config core.hooksPath .githooks
git config commit.template .gitmessage

echo "Enabled .githooks/commit-msg and .gitmessage for this clone."
