# socket_events.py
import asyncio
import logging
from datetime import datetime, timedelta

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import socketio
from app.services.ips.adapter import IPSPacketAdapter
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import AsyncSessionLocal
from app.services.ips.engine import IPSEngine
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


async def get_ips_stats(session: AsyncSession):
    """Get IPS statistics with proper session management"""
    # Get total active rules
    rules_result = await session.execute(
        select(func.count(IPSRule.id)).where(IPSRule.is_active == True)
    )
    total_rules = rules_result.scalar_one()

    # Get recent events (last hour)
    recent_events_result = await session.execute(
        select(func.count(IPSEvent.id)).where(
            IPSEvent.timestamp >= datetime.now() - timedelta(hours=1)
        )
    )
    recent_events = recent_events_result.scalar_one()

    # Get top 5 threats in last hour
    top_threats_result = await session.execute(
        select(
            IPSEvent.rule_id, IPSEvent.category, func.count(IPSEvent.id).label("count")
        )
        .where(IPSEvent.timestamp >= datetime.now() - timedelta(hours=1))
        .group_by(IPSEvent.rule_id, IPSEvent.category)
        .order_by(func.count(IPSEvent.id).desc())
        .limit(5)
    )

    return {
        "total_rules": total_rules,
        "recent_events": recent_events,
        "top_threats": [
            {"rule_id": row.rule_id, "category": row.category, "count": row.count}
            for row in top_threats_result.all()
        ],
    }


async def emit_ips_updates():
    """Background task to send periodic IPS updates with proper session handling"""
    while True:
        try:
            async with AsyncSessionLocal() as session:  # Create new session
                async with session.begin():
                    stats = await get_ips_stats(session)
                    await sio.emit("ips_stats_update", stats)
                    logger.debug("Sent IPS stats update")

                # Wait after successful update
                await asyncio.sleep(60)

        except Exception as e:
            logger.error(f"Error in IPS stats update: {str(e)}", exc_info=True)
            # Wait longer on error
            await asyncio.sleep(300)


async def start_event_emitter():
    """Start background tasks with proper session management"""
    try:
        logger.info("Starting IPS updates emitter")
        await emit_ips_updates()
    except Exception as e:
        logger.error(f"IPS updates emitter failed: {str(e)}", exc_info=True)
        raise


def get_socket_app(fastapi_app):
    """Create ASGI app combining FastAPI and Socket.IO"""
    from socketio import ASGIApp

    return ASGIApp(sio, other_asgi_app=fastapi_app)
