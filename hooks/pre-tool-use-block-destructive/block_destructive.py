#!/usr/bin/env python3
"""PreToolUse hook that blocks destructive Bash commands."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


BLOCK_RULES = (
    (
        "rm -rf",
        re.compile(
            r"(?is)(?:^|[\s;&|()])rm\s+"
            r"(?:-[^\s;|&]*r[^\s;|&]*f[^\s;|&]*|-[^\s;|&]*f[^\s;|&]*r[^\s;|&]*)\b"
        ),
        "Recursive forced deletion is blocked.",
    ),
    (
        "DROP TABLE",
        re.compile(r"(?is)\bdrop\s+table\b"),
        "DROP TABLE statements are blocked.",
    ),
    (
        "git push --force",
        re.compile(r"(?is)(?:^|[\s;&|()])git\s+push\b[^\n;&|]*\s(?:--force|-f)\b"),
        "Force-pushing is blocked.",
    ),
    (
        "TRUNCATE",
        re.compile(r"(?is)\btruncate\b"),
        "TRUNCATE statements are blocked.",
    ),
)

DELETE_FROM = re.compile(r"(?is)\bdelete\s+from\b")
WHERE = re.compile(r"(?is)\bwhere\b")


def find_block_reason(command: str) -> str | None:
    for name, pattern, reason in BLOCK_RULES:
        if pattern.search(command):
            return f"{reason} Matched pattern: {name}."

    for statement in split_sql_statements(command):
        if DELETE_FROM.search(statement) and not WHERE.search(statement):
            return "DELETE FROM without a WHERE clause is blocked. Matched pattern: DELETE FROM."

    return None


def split_sql_statements(command: str) -> list[str]:
    return [part.strip() for part in re.split(r"[;\n]", command) if part.strip()]


def hook_output(decision: str | None = None, reason: str | None = None) -> dict:
    if decision is None:
        return {"continue": True, "suppressOutput": True}

    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }


def log_blocked_attempt(command: str, cwd: str, reason: str) -> None:
    log_dir = Path.home() / ".claude" / "hooks"
    log_dir.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "project_path": cwd,
        "reason": reason,
    }
    with (log_dir / "blocked.log").open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(entry, ensure_ascii=False) + "\n")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(
            json.dumps(
                hook_output(
                    "deny",
                    f"Could not parse PreToolUse hook input as JSON: {exc}",
                )
            )
        )
        return 0

    if payload.get("tool_name") != "Bash":
        print(json.dumps(hook_output()))
        return 0

    tool_input = payload.get("tool_input") or {}
    command = tool_input.get("command") or ""
    cwd = payload.get("cwd") or os.getcwd()
    reason = find_block_reason(command)

    if reason is None:
        print(json.dumps(hook_output()))
        return 0

    log_blocked_attempt(command, cwd, reason)
    print(json.dumps(hook_output("deny", reason)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
