"""Structured (JSON) logging with secret redaction.

Every log line is a JSON object so analysis runs can be audited and parsed
(analysis_id, plugin, start/end, status, duration). A redaction filter makes
sure API keys, passwords and bearer tokens never reach the log sink.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any

_SECRET_KEYS = re.compile(r"(api[_-]?key|password|secret|token|authorization)", re.I)
_BEARER = re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]+", re.I)
_KV_SECRET = re.compile(r"((?:api[_-]?key|password|secret|token)\s*[=:]\s*)\S+", re.I)

_STD_ATTRS = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}


def redact(value: Any) -> Any:
    if isinstance(value, str):
        return _KV_SECRET.sub(r"\1[REDACTED]", _BEARER.sub(r"\1[REDACTED]", value))
    if isinstance(value, dict):
        return {k: ("[REDACTED]" if _SECRET_KEYS.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        for key, val in record.__dict__.items():
            if key not in _STD_ATTRS and not key.startswith("_"):
                payload[key] = redact(val) if not _SECRET_KEYS.search(key) else "[REDACTED]"
        if record.exc_info:
            payload["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    # Keep third-party noise down.
    for noisy in ("httpx", "httpcore", "multipart", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
