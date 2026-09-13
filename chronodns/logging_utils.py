"""Structured, colourised logging for Chrono-DNS."""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import time
from pathlib import Path
from typing import Any

_LEVEL_COLOURS = {
    "DEBUG": "\033[38;5;244m",
    "INFO": "\033[38;5;39m",
    "WARNING": "\033[38;5;214m",
    "ERROR": "\033[38;5;203m",
    "CRITICAL": "\033[48;5;196m\033[38;5;231m",
}
_RESET = "\033[0m"
_DIM = "\033[38;5;240m"


class ConsoleFormatter(logging.Formatter):
    """Human-friendly single-line format with colour."""

    def format(self, record: logging.LogRecord) -> str:
        colour = _LEVEL_COLOURS.get(record.levelname, "")
        ts = time.strftime("%H:%M:%S", time.localtime(record.created))
        name = record.name.replace("chronodns.", "")
        return (
            f"{_DIM}{ts}{_RESET} "
            f"{colour}{record.levelname:<8}{_RESET} "
            f"{_DIM}{name:<22}{_RESET} {record.getMessage()}"
        )


class JSONFormatter(logging.Formatter):
    """Machine-readable NDJSON — ready for Loki / ELK / Splunk ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in getattr(record, "__dict__", {}).items():
            if key.startswith("evt_"):
                payload[key[4:]] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"))


def setup_logging(level: str = "INFO", log_file: str | Path | None = None,
                  quiet: bool = False) -> logging.Logger:
    """Configure the root 'chronodns' logger. Idempotent."""
    logger = logging.getLogger("chronodns")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    logger.propagate = False

    if not quiet:
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(ConsoleFormatter())
        logger.addHandler(console)

    if log_file:
        path = Path(log_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        rotating = logging.handlers.RotatingFileHandler(
            path, maxBytes=8 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        rotating.setFormatter(JSONFormatter())
        logger.addHandler(rotating)

    return logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"chronodns.{name}")
