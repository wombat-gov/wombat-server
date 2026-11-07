"""Structured logging, request correlation, and secret redaction."""
from __future__ import annotations

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import datetime, timezone

from wombat_server import __version__
from wombat_server.config import settings

# Set by RequestContextMiddleware for the lifetime of one request.
request_id_var: ContextVar[str] = ContextVar("wombat_request_id", default="")

_REDACT_PATTERNS = [
    # key=value / key: value forms, including DSNs.
    re.compile(
        r"(?i)\b(password|passwd|secret|token|authorization|cookie|api[_-]?key|"
        r"database_url|runtime_database_url|dsn)\b\s*[=:]\s*(\S+)"
    ),
    # Bearer tokens in free text.
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
]


def redact(value: str) -> str:
    """Replace likely credential material in a log message."""
    text = _REDACT_PATTERNS[0].sub(lambda m: f"{m.group(1)}=[REDACTED]", value)
    return _REDACT_PATTERNS[1].sub("Bearer [REDACTED]", text)


class RedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    key: redact(val) if isinstance(val, str) else val
                    for key, val in record.args.items()
                }
            else:
                record.args = tuple(
                    redact(arg) if isinstance(arg, str) else arg for arg in record.args
                )
        return True


class JsonFormatter(logging.Formatter):
    """One JSON object per line, suitable for Loki/ELK/CloudWatch."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact(record.getMessage()),
            "service": "wombat-server",
            "version": __version__,
            "request_id": getattr(record, "request_id", "") or request_id_var.get(),
        }
        for field in ("method", "path", "status", "duration_ms", "user_id"):
            if hasattr(record, field):
                payload[field] = getattr(record, field)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging() -> None:
    """Install the process-wide handler. Safe to call more than once."""
    level = getattr(logging, settings.wombat_log_level.upper(), logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    if settings.wombat_log_format.lower() == "text":
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        )
    else:
        handler.setFormatter(JsonFormatter())
    handler.addFilter(RedactionFilter())

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)

    # Our request middleware emits one structured line per request; the
    # framework access log would duplicate it without the same fields.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
