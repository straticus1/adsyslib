import logging
from rich.logging import RichHandler
from typing import Optional

def configure_logging(level: int = logging.INFO, log_file: Optional[str] = None):
    """
    Configure logging with RichHandler for beautiful console output,
    and optionally a file handler for audit trails.
    """
    handlers = [
        RichHandler(
            rich_tracebacks=True,
            show_time=True,
            show_path=False,
            markup=True
        )
    ]

    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        handlers.append(file_handler)

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
        force=True
    )

    # Silence noisy libraries if necessary
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("botocore").setLevel(logging.WARNING)

def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
