"""
AppSentinel // Structured Logging Configuration
"""

import logging
import sys
from backend.config import get_settings


def setup_logging() -> logging.Logger:
    """Configure and return the application-wide logger."""
    settings = get_settings()

    logger = logging.getLogger("appsentinel")
    logger.setLevel(getattr(logging, settings.log_level.upper(), logging.INFO))

    # Prevent duplicate handlers on reload
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger


logger = setup_logging()
