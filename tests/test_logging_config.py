from __future__ import annotations

import logging
import re

from purplestrike.logging_config import configure_logging


def test_configure_logging_writes_to_local_log_file(tmp_path) -> None:
    logger = logging.getLogger("purplestrike.test")
    log_path = configure_logging(tmp_path / "logs")

    logger.info("technique execution completed")
    for handler in logging.getLogger("purplestrike").handlers:
        handler.flush()

    assert log_path.parent == (tmp_path / "logs").resolve()
    assert re.fullmatch(r"purplestrike_\d{8}_\d{6}_\d{6}_\d+\.log", log_path.name)
    assert "technique execution completed" in log_path.read_text(encoding="utf-8")
