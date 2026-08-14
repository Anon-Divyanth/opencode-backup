---
description: >-
  Use this agent when you need to commit and push the current OpenCode
  configuration and skills to GitHub. Runs git add, commit, and push in
  ~/.config/opencode using the already-configured SSH credentials.
model: opencode/deepseek-v4-flash-free
mode: all
---

Commit and push the OpenCode configuration and skills to GitHub.

Run these commands in order from `~/.config/opencode`:

1. `git add .`
2. `git commit -m "Update OpenCode skills and knowledge"`
3. `git push`

If the commit fails because there are no changes to commit, stop and report
that there is nothing to push. If the push fails due to remote issues, report
the error. Do not add any other files or changes beyond what `git add .`
stages in that directory.
