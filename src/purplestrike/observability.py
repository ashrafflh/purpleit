"""Structured execution events shared by file and console logging."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

from purplestrike.models.config import PurpleStrikeConfig

_context: ContextVar[dict[str, Any] | None] = ContextVar("execution_log_context", default=None)
_redactor: ContextVar[LogRedactor | None] = ContextVar("execution_log_redactor", default=None)
_sensitive_key = re.compile(
    r"password|passwd|secret|token|api[_-]?key|authorization|credential|private[_-]?key",
    re.IGNORECASE,
)


@contextmanager
def log_context(redactor: LogRedactor | None = None, **values: Any) -> Iterator[None]:
    token = _context.set({**(_context.get() or {}), **values})
    redactor_token = _redactor.set(redactor or _redactor.get())
    try:
        yield
    finally:
        _context.reset(token)
        _redactor.reset(redactor_token)


class ExecutionFormatter(logging.Formatter):
    """Also protect legacy messages and tracebacks emitted inside a run."""

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        redactor = _redactor.get()
        return str(redactor.redact(rendered)) if redactor else rendered


class LogRedactor:
    """Redact structured credentials and their echoes without shortening evidence."""

    def __init__(self, config: PurpleStrikeConfig) -> None:
        self.config = config
        self._secrets: set[str] = set()

    def _remember(self, value: Any) -> None:
        if isinstance(value, str) and value:
            self._secrets.add(value)
        elif isinstance(value, dict):
            for item in value.values():
                self._remember(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self._remember(item)

    def _collect(self, value: Any) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if _sensitive_key.search(str(key)):
                    self._remember(item)
                else:
                    self._collect(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                self._collect(item)

    def redact(self, value: Any) -> Any:
        self._remember(
            [
                self.config.target_password,
                self.config.siem.api_password,
                self.config.llm.api_key,
            ]
        )
        for server in self.config.mcp.servers.values():
            self._collect(server.env)
            self._collect(server.headers)
        self._collect(value)
        return self._clean(value)

    def _clean(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                str(key): "[REDACTED]" if _sensitive_key.search(str(key)) else self._clean(item)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [self._clean(item) for item in value]
        if isinstance(value, str):
            variants = {
                variant
                for secret in self._secrets
                for variant in (
                    secret,
                    secret.replace("'", "''"),
                    json.dumps(secret, ensure_ascii=False)[1:-1],
                )
            }
            for secret in sorted(variants, key=len, reverse=True):
                value = value.replace(secret, "[REDACTED]")
            # Escape terminal control characters while leaving printable output intact.
            return value.replace("\x1b", r"\u001b")
        return value

    def response(self, raw: str) -> Any:
        """Keep malformed model replies visible, and redact JSON credential fields."""
        candidate = raw.strip()
        if candidate.startswith("```") and "\n" in candidate:
            candidate = candidate.split("\n", 1)[1].rsplit("```", 1)[0]
        try:
            return self.redact(json.loads(candidate))
        except (ValueError, TypeError):
            return self.redact(raw)


class AuditLogger:
    def __init__(
        self,
        logger: logging.Logger,
        config: PurpleStrikeConfig,
        redactor: LogRedactor | None = None,
    ) -> None:
        self.logger = logger
        self.redactor = redactor or LogRedactor(config)

    def event(self, event: str, *, level: int = logging.INFO, **details: Any) -> None:
        payload = self.redactor.redact({**(_context.get() or {}), **details})
        self.logger.log(
            level,
            "%s\n%s",
            event,
            json.dumps(payload, indent=2, ensure_ascii=False, default=str),
        )
