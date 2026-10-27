#!/bin/bash
# git_save.sh "message" — stage ALL changes, commit, push to GitHub (1:1 mirror)
# FIX (2026-10-28): was `git add scripts/ worklog.md` — silently dropped
# .github/, rust/, root files → lost-source incident. Now `git add -A`
# with .gitignore as the only filter.
cd /home/z/my-project || exit 1
MSG="${1:-autosave $(date -u +%Y-%m-%dT%H:%M:%SZ)}"

# never commit secrets / env
if [ -f .env ]; then git add -A -- ':!.env' 2>/dev/null || true; else git add -A; fi

if git diff --cached --quiet 2>/dev/null && [ -z "$(git diff --cached --name-only)" ]; then
  echo "[git_save] nothing to commit"
else
  git commit -q -m "$MSG" && echo "[git_save] committed: $MSG" || echo "[git_save] commit FAILED"
fi

if git push -q origin main 2>/dev/null; then
  echo "[git_save] pushed ✓"
else
  # remote moved (runner commits?) — rebase local on top, retry once
  git pull --rebase -q -X ours origin main 2>/dev/null
  git push -q origin main 2>/dev/null && echo "[git_save] pushed after rebase ✓" || echo "[git_save] push FAILED"
fi
