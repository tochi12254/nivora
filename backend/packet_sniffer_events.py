# packet_sniffer_events.py
import logging
from socketio import AsyncNamespace
from multiprocessing import Queue
from typing import Any, Dict

logger = logging.getLogger(__name__)


class PacketSnifferNamespace(AsyncNamespace):
    def __init__(self, namespace: str, sio_queue: Queue):
        super().__init__(namespace)
        self.sio_queue = sio_queue
        logger.info("Initialized PacketSnifferNamespace for %s ", namespace)

    async def on_connect(self, sid: str, environ: Dict[str, Any]):
        logger.info("Client connected to packet sniffer namespace: %s", sid)

    async def on_disconnect(self, sid: str):
        logger.info("Client disconnected from packet sniffer namespace: %s ", sid)

