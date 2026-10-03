from __future__ import annotations

import logging
import os
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOGGER_NAME = "purplestrike"
_FILE_HANDLER_NAME = "purplestrike_file"
_CONSOLE_HANDLER_NAME = "purplestrike_console"


def configure_logging(log_dir: str | Path = "logs") -> Path:
    """Persist PurpleStrike logs locally while keeping warnings visible on stderr."""
    directory = Path(log_dir).expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)

    package_logger = logging.getLogger(_LOGGER_NAME)
    package_logger.setLevel(logging.DEBUG)
    package_logger.propagate = False

    for handler in package_logger.handlers:
        if isinstance(handler, RotatingFileHandler) and handler.name == _FILE_HANDLER_NAME:
            return Path(handler.baseFilename)

    timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S_%f")
    log_path = directory / f"purplestrike_{timestamp}_{os.getpid()}.log"

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    file_handler.set_name(_FILE_HANDLER_NAME)
    package_logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(formatter)
    console_handler.set_name(_CONSOLE_HANDLER_NAME)
    package_logger.addHandler(console_handler)

    package_logger.info("File logging initialized at %s", log_path)
    return log_path
