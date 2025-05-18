# hypercorn_config.py
from hypercorn.config import Config
from hypercorn.utils import write_pid_file
import os
import logging

logger = logging.getLogger(__name__)


def configure_hypercorn():
    config = Config()
    config.bind = ["0.0.0.0:8000"]

    # Set explicit PID file path
    config.pid_path = os.path.join(
        os.getenv("TEMP", "."), "hypercorn.pid"  # Windows-compatible path
    )

    # Windows-specific optimizations
    if os.name == "nt":
        config.backlog = 500
        config.socket_options = [
            (socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
            (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
        ]

    try:
        write_pid_file(config.pid_path)
    except Exception as e:
        logger.warning(f"Couldn't write PID file: {str(e)}")

    return config
