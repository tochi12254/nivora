# socket_events.py
import asyncio
import logging
from datetime import datetime, timedelta

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import socketio
# from app.services.ips.adapter import IPSPacketAdapter
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import AsyncSessionLocal
# from app.services.ips.engine import IPSEngine
from app.models.ips import IPSRule, IPSEvent
from sio_instance import sio

logger = logging.getLogger(__name__)


@sio.event
async def connect(sid, environ):
    """Handle new socket.io connections"""
    logger.info(f"Client connected: {sid}")
    await sio.emit("ips_status", {"status": "active"}, room=sid)


@sio.event
async def disconnect(sid):
    """Handle socket.io disconnections"""
    logger.info(f"Client disconnected: {sid}")

@sio.on("start_sniffing")
async def _on_start_sniffing(sid, data):
    logger.info(f"User started sniffing on {data.get('sniffingInterface')}")
    # try:
    #     await sniffer.start(interface)
    #     await sniffer_service.start()
    #     await sio.emit("sniffing_started", {"interface": interface}, to=sid)
    # except Exception as e:
    #     logger.error(f"Error starting sniffer: {str(e)}")
    #     await sio.emit("sniffing_error", {"error": str(e)}, to=sid)
@sio.on("stop_sniffing")
async def _on_stop_sniffing(sid):
    logger.info("User stopped sniffing")
    # try:
    #     sniffer.stop()
    #     await sniffer_service.stop()
    #     await sio.emit("sniffing_stopped", {}, to=sid)
    # except Exception as e:
    #     logger.error(f"Error stopping sniffer: {str(e)}")
    #     await sio.emit("sniffing_error", {"error": str(e)}, to=sid)

def get_socket_app(fastapi_app):
    """Create ASGI app combining FastAPI and Socket.IO"""
    from socketio import ASGIApp

    return ASGIApp(sio, other_asgi_app=fastapi_app)
