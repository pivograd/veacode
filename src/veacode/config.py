"""Validated, explicit routes. Credentials belong in the clients or environment."""

import math
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Route


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Config:
    routes: dict[str, Route]
    routing: dict[str, list[str]]
    allow_deepseek: bool = False
    max_repairs: int = 1
    check_timeout_seconds: float = 120

    def route_names(self, phase: str, kind: str = "implementation") -> list[str]:
        key = kind if phase == "execute" and kind in self.routing else phase
        return list(self.routing.get(key, []))

    def permitted(self, route: Route) -> bool:
        return route.billing != "deepseek_api" or self.allow_deepseek


def _positive(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{label} must be a positive number")
    if not math.isfinite(value) or value <= 0:
        raise ConfigError(f"{label} must be a positive finite number")
    return float(value)


def load_config(path: Path) -> Config:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"Cannot read configuration: {exc}") from exc
    return config_from_dict(raw)


def config_from_dict(raw: dict[str, Any]) -> Config:
    unknown = set(raw) - {"routes", "routing", "policy"}
    if unknown:
        raise ConfigError(f"Unknown configuration sections: {sorted(unknown)}")
    policy = raw.get("policy", {})
    if not isinstance(policy, dict) or set(policy) - {
        "allow_deepseek",
        "max_repairs",
        "check_timeout_seconds",
    }:
        raise ConfigError("Unknown or invalid policy settings")
    allow = policy.get("allow_deepseek", False)
    repairs = policy.get("max_repairs", 1)
    if not isinstance(allow, bool):
        raise ConfigError("allow_deepseek must be true or false")
    if type(repairs) is not int or not 0 <= repairs <= 5:
        raise ConfigError("max_repairs must be an integer between 0 and 5")
    routes: dict[str, Route] = {}
    definitions = raw.get("routes", {})
    if not isinstance(definitions, dict) or not definitions:
        raise ConfigError("At least one route is required")
    combinations = {
        ("codex", "openai", "chatgpt_subscription"),
        ("claude", "anthropic", "claude_subscription"),
        ("opencode", "deepseek", "deepseek_api"),
    }
    allowed_fields = {
        "harness",
        "model",
        "provider",
        "billing",
        "effort",
        "profile",
        "executable",
        "timeout_seconds",
        "env",
    }
    for name, item in definitions.items():
        if not isinstance(item, dict) or set(item) - allowed_fields:
            raise ConfigError(f"Unknown or invalid settings for route {name}")
        for key in ("harness", "model", "provider", "billing"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise ConfigError(f"Route {name} requires a nonempty {key}")
        if (item["harness"], item["provider"], item["billing"]) not in combinations:
            raise ConfigError(f"Unsupported harness/provider/billing combination for {name}")
        if item["harness"] == "opencode" and "/" in item["model"]:
            raise ConfigError("OpenCode model must be a bare DeepSeek model ID, without provider/")
        for key in ("effort", "profile", "executable"):
            if key in item and (not isinstance(item[key], str) or not item[key].strip()):
                raise ConfigError(f"Route {name}: {key} must be a nonempty string")
        env = item.get("env", {})
        if not isinstance(env, dict) or set(env) - {"CODEX_HOME"}:
            raise ConfigError("Only CODEX_HOME may be set in route env; keep keys out of TOML")
        if any(not isinstance(value, str) or not value for value in env.values()):
            raise ConfigError("Route env values must be nonempty strings")
        timeout = _positive(item.get("timeout_seconds", 900), "timeout_seconds")
        routes[name] = Route(name=name, **{**item, "timeout_seconds": timeout})
    routing = raw.get("routing", {})
    if not isinstance(routing, dict):
        raise ConfigError("routing must be a table")
    for phase in ("plan", "execute", "review"):
        if not routing.get(phase):
            raise ConfigError(f"routing.{phase} must contain at least one route")
    for phase, names in routing.items():
        if (
            not isinstance(names, list)
            or not names
            or any(not isinstance(name, str) or name not in routes for name in names)
            or len(set(names)) != len(names)
        ):
            raise ConfigError(f"Invalid route list for {phase}")
    return Config(
        routes,
        routing,
        allow,
        repairs,
        _positive(policy.get("check_timeout_seconds", 120), "check_timeout_seconds"),
    )
