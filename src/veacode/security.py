"""Best-effort log redaction, shared by controller-owned artifacts."""

import os
import re
from typing import Any

_KEY_NAME = re.compile(r"(token|password|secret|api[_-]?key|authorization)", re.I)
_CREDENTIAL_FIELD = re.compile(
    r"^(?:authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"auth[_-]?token|token|password|secret|client[_-]?secret)$",
    re.I,
)
_TOKEN = re.compile(r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{16,})\b")
_ASSIGNMENT = re.compile(
    r"(?i)((?:api[_-]?key|auth[_-]?token|password|secret|authorization)"
    r"[\"']?\s*[:=]\s*[\"']?)(?:Bearer\s+)?[^\s\"',;}]+"
)


def redact(value: Any) -> Any:
    if isinstance(value, str):
        for key, secret in os.environ.items():
            if _KEY_NAME.search(key) and len(secret) >= 8:
                value = value.replace(secret, "<redacted>")
        return _ASSIGNMENT.sub(r"\1<redacted>", _TOKEN.sub("<redacted>", value))
    if isinstance(value, dict):
        return {
            key: "<redacted>" if _CREDENTIAL_FIELD.fullmatch(str(key)) else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, (tuple, list)):
        return [redact(item) for item in value]
    return value
