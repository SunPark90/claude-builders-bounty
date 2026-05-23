# Block Destructive Bash Commands

Claude Code `PreToolUse` hook that denies dangerous Bash commands before they run.

## Installation

```bash
python3 install.py
```

The installer copies `block_destructive.py` to `~/.claude/hooks/` and adds a Bash `PreToolUse` hook to `~/.claude/settings.json`.

## What It Blocks

- `rm -rf` and `rm -fr`
- `rm -Rf`, `rm -fR`, and `rm --recursive --force`
- `DROP TABLE`, `DROP DATABASE`, and `DROP SCHEMA`
- `git push --force`, `git push -f`, and `git push --force-with-lease`
- `TRUNCATE`
- `DELETE FROM` statements without a `WHERE` clause
- direct block-device writes such as `mkfs`, `dd ... of=/dev/sd*`, and redirects to `/dev/sd*`
- recursive permissive root-path permission changes such as `chmod -R 777 /...`

Every blocked attempt is appended to `~/.claude/hooks/blocked.log` as JSON Lines with:

- timestamp
- attempted command
- project path
- block reason

## Hook Behavior

The hook reads Claude Code hook JSON from stdin. Non-Bash tool calls are allowed. Safe Bash commands return `continue: true`. Blocked commands return a `PreToolUse` `permissionDecision` of `deny` with a reason Claude can use to choose a safer command.
