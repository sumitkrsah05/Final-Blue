"""Logging setup — loguru sinks rendered through a shared rich console.

Import :func:`get_logger` anywhere; call :func:`configure_logging` once from the
application entry point.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from loguru import logger
from rich.console import Console

console = Console(stderr=False)
"""Shared rich console for human-facing output (tables, panels, progress)."""

_CONSOLE_FORMAT = (
    "<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | "
    "<cyan>{name}</cyan> - <level>{message}</level>"
)
_configured = False


def configure_logging(level: str = "INFO", log_file: Optional[Path] = None) -> None:
    """Install the console sink (and an optional rotating file sink).

    Safe to call more than once; the previous sinks are replaced rather than
    duplicated.
    """
    global _configured
    logger.remove()
    logger.add(
        sys.stderr,
        level=level.upper(),
        format=_CONSOLE_FORMAT,
        colorize=True,
        backtrace=False,
        diagnose=False,
    )
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        logger.add(
            log_file,
            level="DEBUG",
            rotation="5 MB",
            retention=3,
            encoding="utf-8",
            backtrace=True,
            diagnose=False,
        )
    _configured = True


def get_logger(name: str):
    """Return a logger bound to ``name``, configuring defaults on first use."""
    if not _configured:
        configure_logging()
    return logger.bind(name=name)


__all__ = ["configure_logging", "get_logger", "console", "logger"]
