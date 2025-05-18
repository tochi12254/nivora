from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from typing import List, Dict
from datetime import datetime, timedelta
import asyncio
import json

from services.monitoring.packet import PacketSniffer
from services.websocket_manager import WebSocketManager
from models.log import NetworkLog
from app.database import get_db
from sqlalchemy.orm import Session
from sqlalchemy import desc

router = APIRouter()
packet_sniffer = PacketSniffer()
ws_manager = WebSocketManager()


@router.on_event("startup")
async def startup_event():
    # Start packet sniffing in background
    asyncio.create_task(packet_sniffer.start_sniffing(interface="Wi-Fi"))


from app.database import check_db_health


@router.get("/health")
async def health_check():
    db_ok = await check_db_health()
    return {"database": "ok" if db_ok else "unavailable"}


@router.get("/stats", response_model=Dict[str, int])
async def get_network_stats():
    """Get current network statistics"""
    stats = await packet_sniffer.get_network_stats()
    return stats


@router.get("/threats", response_model=List[Dict])
async def get_recent_threats(db: Session = Depends(get_db), limit: int = 100):
    """Get recently detected threats"""
    threats = (
        db.query(NetworkLog).order_by(desc(NetworkLog.timestamp)).limit(limit).all()
    )
    return [
        {
            "timestamp": threat.timestamp,
            "threat_type": threat.threat_type,
            "source_ip": threat.source_ip,
            "destination_ip": threat.destination_ip,
            "protocol": threat.protocol,
        }
        for threat in threats
    ]


@router.get("/connections", response_model=List[Dict])
async def get_active_connections():
    """Get currently active network connections"""
    # This would return the connection tracking data from the packet sniffer
    return []


@router.websocket("/ws/network")
async def websocket_network_monitor(websocket: WebSocket):
    """WebSocket endpoint for real-time network monitoring"""
    await ws_manager.connect(websocket, "network_monitor")

    try:
        # Send initial stats
        stats = await packet_sniffer.get_network_stats()
        await websocket.send_json({"type": "initial_stats", "data": stats})

        # Keep connection alive
        while True:
            await asyncio.sleep(5)
            stats = await packet_sniffer.get_network_stats()
            await websocket.send_json({"type": "stats_update", "data": stats})

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, "network_monitor")
    except Exception as e:
        print(f"WebSocket error: {str(e)}")
        await websocket.close(code=1011)
