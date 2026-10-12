from __future__ import annotations

import logging
import re
from contextlib import contextmanager

import pytest

from purplestrike.logging_config import configure_logging


@contextmanager
def isolated_logging():
    package_logger = logging.getLogger("purplestrike")
    handlers = package_logger.handlers[:]
    level, propagate = package_logger.level, package_logger.propagate
    package_logger.handlers = []
    try:
        yield
    finally:
        for handler in package_logger.handlers:
            handler.close()
        package_logger.handlers = handlers
        package_logger.setLevel(level)
        package_logger.propagate = propagate


@pytest.fixture(autouse=True)
def isolate_handlers():
    with isolated_logging():
        yield


def test_configure_logging_writes_to_local_log_file(tmp_path, capsys) -> None:
    logger = logging.getLogger("purplestrike.test")
    log_path = configure_logging(tmp_path / "logs")

    logger.info("technique execution completed")
    for handler in logging.getLogger("purplestrike").handlers:
        handler.flush()

    assert log_path.parent == (tmp_path / "logs").resolve()
    assert re.fullmatch(r"purplestrike_\d{8}_\d{6}_\d{6}_\d+\.log", log_path.name)
    assert "technique execution completed" in log_path.read_text(encoding="utf-8")
    assert "technique execution completed" in capsys.readouterr().err


def test_logging_is_idempotent_and_keeps_debug_prompts_in_file(tmp_path, capsys):
    path = configure_logging(tmp_path)
    assert configure_logging(tmp_path) == path
    logger = logging.getLogger("purplestrike.test")
    logger.info("one console event")
    logger.debug("detailed prompt")
    assert capsys.readouterr().err.count("one console event") == 1
    content = path.read_text(encoding="utf-8")
    assert "detailed prompt" in content
