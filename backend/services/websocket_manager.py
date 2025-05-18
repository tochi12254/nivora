import asyncio
from typing import Dict, List
from fastapi import WebSocket
import json
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


class WebSocketManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = defaultdict(list)
        self.subscriptions: Dict[str, List[str]] = defaultdict(list)
        self.keep_alive_task = None

    async def connect(self, websocket: WebSocket, client_id: str):
        await websocket.accept()
        self.active_connections[client_id].append(websocket)
        logger.info(f"Client connected: {client_id}")

    def disconnect(self, websocket: WebSocket, client_id: str):
        if client_id in self.active_connections:
            self.active_connections[client_id].remove(websocket)
            if not self.active_connections[client_id]:
                del self.active_connections[client_id]
        logger.info(f"Client disconnected: {client_id}")

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: Dict, sender: str = None):
        """Broadcast message to all connected clients"""
        for client_id, connections in self.active_connections.items():
            for connection in connections:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error sending to {client_id}: {str(e)}")
                    self.disconnect(connection, client_id)

    async def send_to_channel(self, channel: str, message: Dict):
        """Send message to clients subscribed to a specific channel"""
        for client_id in self.subscriptions.get(channel, []):
            for connection in self.active_connections.get(client_id, []):
                try:
                    await connection.send_json({"channel": channel, "data": message})
                except Exception as e:
                    logger.error(f"Error sending to {client_id}: {str(e)}")
                    self.disconnect(connection, client_id)

    async def subscribe(
        self, websocket: WebSocket, client_id: str, channels: List[str]
    ):
        """Subscribe client to specific channels"""
        for channel in channels:
            if client_id not in self.subscriptions[channel]:
                self.subscriptions[channel].append(client_id)
        await websocket.send_json(
            {
                "type": "subscription_update",
                "message": f"Subscribed to {', '.join(channels)}",
            }
        )

    async def unsubscribe(
        self, websocket: WebSocket, client_id: str, channels: List[str]
    ):
        """Unsubscribe client from specific channels"""
        for channel in channels:
            if client_id in self.subscriptions.get(channel, []):
                self.subscriptions[channel].remove(client_id)
        await websocket.send_json(
            {
                "type": "subscription_update",
                "message": f"Unsubscribed from {', '.join(channels)}",
            }
        )

    async def keep_alive(self):
        """Send periodic ping messages to keep connections alive"""
        while True:
            await asyncio.sleep(30)  # Send ping every 30 seconds
            for client_id, connections in self.active_connections.items():
                for connection in connections:
                    try:
                        await connection.send_json({"type": "ping"})
                    except Exception as e:
                        logger.error(f"Keep-alive failed for {client_id}: {str(e)}")
                        self.disconnect(connection, client_id)
