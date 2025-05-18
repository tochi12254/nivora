# sio_instance.py
from socketio import ASGIApp, AsyncServer
import logging
from app.core.config import settings
import os


logger = logging.getLogger(__name__)



sio = AsyncServer(
    async_mode="asgi",
    cors_allowed_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    logger=False,
    engineio_logger=settings.DEBUG,
)

