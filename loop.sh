#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

if [ ! -d .git ]; then
  git init
  git add -A
  git commit -m "init: project skeleton (CLAUDE.md, TASKS.md, PROMPT.md, loop.sh)"
fi

while grep -q '^\- \[ \]' TASKS.md; do
  echo "=== loop pass: $(date) ==="
  claude -p "$(cat PROMPT.md)" --dangerously-skip-permissions

  if ! git diff --quiet || ! git diff --cached --quiet; then
    git add -A
    git commit -m "loop pass: $(date +%s)" || true
  fi
done

echo "All tasks in TASKS.md are checked off. Stopping."
