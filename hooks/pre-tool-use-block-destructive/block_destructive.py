#!/usr/bin/env python3
"""PreToolUse hook that blocks destructive Bash commands."""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path


DROP_DDL = re.compile(r"(?is)\bdrop\s+(table|database|schema)\b")
DELETE_FROM = re.compile(r"(?is)\bdelete\s+from\b")
TRUNCATE = re.compile(r"(?is)\btruncate\b")
WHERE = re.compile(r"(?is)\bwhere\b")


def find_block_reason(command: str) -> str | None:
    if has_rm_recursive_force(command):
        return "Recursive forced deletion is blocked. Matched pattern: rm -rf."

    if has_forced_git_push(command):
        return "Force-pushing is blocked. Matched pattern: git push --force."

    if DROP_DDL.search(command):
        return "Destructive DROP statement is blocked. Matched pattern: DROP TABLE/DATABASE/SCHEMA."

    if TRUNCATE.search(command):
        return "TRUNCATE statements are blocked. Matched pattern: TRUNCATE."

    for statement in split_sql_statements(command):
        if DELETE_FROM.search(statement) and not WHERE.search(statement):
            return "DELETE FROM without a WHERE clause is blocked. Matched pattern: DELETE FROM."

    return None


def has_rm_recursive_force(command: str) -> bool:
    for words in shell_commands(command):
        for index, word in enumerate(words):
            if command_name(word) != "rm":
                continue

            has_recursive = False
            has_force = False
            for option in words[index + 1 :]:
                if option == "--":
                    continue
                if not option.startswith("-") or option == "-":
                    break

                if option == "--recursive":
                    has_recursive = True
                elif option == "--force":
                    has_force = True
                elif option.startswith("--"):
                    continue
                else:
                    flags = option.lstrip("-")
                    has_recursive = has_recursive or "r" in flags.lower()
                    has_force = has_force or "f" in flags

                if has_recursive and has_force:
                    return True

    return False


def has_forced_git_push(command: str) -> bool:
    for words in shell_commands(command):
        for index, word in enumerate(words):
            if command_name(word) != "git":
                continue

            git_args = words[index + 1 :]
            push_index = next(
                (i for i, arg in enumerate(git_args) if arg.lower() == "push"),
                None,
            )
            if push_index is None:
                continue

            push_args = [arg.lower() for arg in git_args[push_index + 1 :]]
            if any(arg in {"--force", "--force-with-lease", "-f"} for arg in push_args):
                return True

    return False


def shell_commands(command: str) -> list[list[str]]:
    segments = re.split(r"(?:&&|\|\||;|\n)", command)
    return [shell_words(segment) for segment in segments if segment.strip()]


def shell_words(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def command_name(word: str) -> str:
    return Path(word).name.lower()


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
    log_dir = hooks_dir()
    log_dir.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "project_path": cwd,
        "reason": reason,
    }
    with (log_dir / "blocked.log").open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(entry, ensure_ascii=False) + "\n")


def hooks_dir() -> Path:
    override = os.environ.get("CLAUDE_HOOKS_DIR")
    if override:
        return Path(override)

    config_dir = os.environ.get("CLAUDE_CONFIG_DIR")
    if config_dir:
        return Path(config_dir) / "hooks"

    return Path.home() / ".claude" / "hooks"


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
