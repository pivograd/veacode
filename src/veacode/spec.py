"""User-owned task specifications; models cannot inject verification commands."""

import tomllib
from pathlib import Path
from typing import Any


def validate_spec(spec: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(spec, dict) or set(spec) - {
        "goal",
        "kind",
        "read_only",
        "checks",
        "constraints",
    }:
        raise ValueError("Unknown or invalid task fields")
    goal = spec.get("goal")
    if not isinstance(goal, str) or not goal.strip() or len(goal) > 50000:
        raise ValueError("Task goal must contain 1..50000 characters")
    kind = spec.get("kind", "implementation")
    if kind not in {"implementation", "simple", "debugging", "research"}:
        raise ValueError("Task kind: implementation, simple, debugging or research")
    read_only = spec.get("read_only", False)
    if not isinstance(read_only, bool):
        raise ValueError("read_only must be true or false")
    checks = spec.get("checks", [])
    if (
        not isinstance(checks, list)
        or len(checks) > 20
        or any(
            not isinstance(command, list)
            or not command
            or any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in command)
            for command in checks
        )
    ):
        raise ValueError("checks must be arrays of command arguments")
    if not checks and not read_only:
        raise ValueError("Code-changing tasks require at least one trusted verification command")
    constraints = spec.get("constraints", [])
    if not isinstance(constraints, list) or any(not isinstance(c, str) for c in constraints):
        raise ValueError("constraints must be an array of strings")
    return {
        "goal": goal.strip(),
        "kind": kind,
        "read_only": read_only,
        "checks": checks,
        "constraints": constraints,
    }


def load_spec(path: Path) -> dict[str, Any]:
    return validate_spec(tomllib.loads(path.read_text(encoding="utf-8-sig")))
