# Block Destructive Bash Commands

Claude Code `PreToolUse` hook that denies dangerous Bash commands before they run.

## Installation

```bash
python3 install.py
```

The installer copies `block_destructive.py` to `~/.claude/hooks/` and adds a Bash `PreToolUse` hook to `~/.claude/settings.json`.

## What It Blocks

- `rm -rf` and `rm -fr`
- `DROP TABLE`
- `git push --force` and `git push -f`
- `TRUNCATE`
- `DELETE FROM` statements without a `WHERE` clause

Every blocked attempt is appended to `~/.claude/hooks/blocked.log` as JSON Lines with:

- timestamp
- attempted command
- project path
- block reason

## Hook Behavior

The hook reads Claude Code hook JSON from stdin. Non-Bash tool calls are allowed. Safe Bash commands return `continue: true`. Blocked commands return a `PreToolUse` `permissionDecision` of `deny` with a reason Claude can use to choose a safer command.
