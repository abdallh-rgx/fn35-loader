#!/bin/bash
# git_save.sh "message" — stage code changes, commit, push to GitHub
cd /home/z/my-project
MSG="${1:-autosave $(date +%H:%M:%S)}"
git add -A scripts/ worklog.md 2>/dev/null
if git diff --cached --quiet 2>/dev/null; then
  echo "[git_save] nothing to commit"
else
  git commit -q -m "$MSG" && echo "[git_save] committed: $MSG"
fi
git push -q origin main 2>&1 && echo "[git_save] pushed ✓" || echo "[git_save] push FAILED"
