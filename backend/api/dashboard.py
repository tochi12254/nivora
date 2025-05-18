from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from datetime import datetime, timedelta
import psutil
import platform
from app.database import get_db
from models.log import NetworkLog
from models.firewall import FirewallLog
from services.monitoring.packet import PacketSniffer
from app.utils.security import JWTBearer, role_required
from schemas.dashboard import (
    SystemStatsResponse,
    ThreatSummaryResponse,
    TrafficSummaryResponse,
    ActivityTimelineResponse,
)

router = APIRouter()
security = HTTPBearer()


@router.get("/stats/system", response_model=SystemStatsResponse)
async def get_system_stats(
    current_user: Dict = Depends(JWTBearer()), db: Session = Depends(get_db)
):
    """
    Get current system statistics including CPU, memory, and network usage
    """
    # CPU and Memory
    cpu_usage = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()

    # Network
    net_io = psutil.net_io_counters()
    disk_io = psutil.disk_usage("/")

    # Security stats
    threat_count = db.query(NetworkLog).count()
    firewall_actions = db.query(FirewallLog).count()

    return {
        "cpu_usage": cpu_usage,
        "memory_usage": memory.percent,
        "memory_total": memory.total,
        "memory_used": memory.used,
        "network_sent": net_io.bytes_sent,
        "network_recv": net_io.bytes_recv,
        "disk_usage": disk_io.percent,
        "threat_count": threat_count,
        "firewall_actions": firewall_actions,
        "uptime": psutil.boot_time(),
        "timestamp": datetime.utcnow(),
    }


@router.get("/stats/threats/summary", response_model=ThreatSummaryResponse)
@role_required(["admin", "security_analyst"])
async def get_threat_summary(
    time_range: str = "24h",
    current_user: Dict = Depends(JWTBearer()),
    db: Session = Depends(get_db),
):
    """
    Get summary of threats detected in the given time range
    """
    time_map = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }

    delta = time_map.get(time_range, timedelta(hours=24))
    since = datetime.utcnow() - delta

    # Threat counts by type
    threat_counts = (
        db.query(NetworkLog.threat_type, func.count(NetworkLog.id).label("count"))
        .filter(NetworkLog.timestamp >= since)
        .group_by(NetworkLog.threat_type)
        .all()
    )

    # Top source IPs
    top_sources = (
        db.query(NetworkLog.source_ip, func.count(NetworkLog.id).label("count"))
        .filter(NetworkLog.timestamp >= since, NetworkLog.source_ip.isnot(None))
        .group_by(NetworkLog.source_ip)
        .order_by(func.count(NetworkLog.id).desc())
        .limit(10)
        .all()
    )

    return {
        "time_range": time_range,
        "total_threats": sum(t.count for t in threat_counts),
        "threats_by_type": {t.threat_type: t.count for t in threat_counts},
        "top_source_ips": [{"ip": t.source_ip, "count": t.count} for t in top_sources],
        "start_time": since,
        "end_time": datetime.utcnow(),
    }


@router.get("/stats/traffic/summary", response_model=TrafficSummaryResponse)
@role_required(["admin", "security_analyst"])
async def get_traffic_summary(
    current_user: Dict = Depends(JWTBearer()),
    sniffer: PacketSniffer = Depends(PacketSniffer),
):
    """
    Get current network traffic statistics
    """
    stats = await sniffer.get_network_stats()

    # Add protocol distribution
    protocols = {"tcp": 0, "udp": 0, "icmp": 0, "other": 0}

    # TODO: Add actual protocol counts from sniffer

    return {
        "active_connections": stats["active_connections"],
        "known_hosts": stats["known_hosts"],
        "threats_detected": stats["threats_detected"],
        "protocol_distribution": protocols,
        "timestamp": datetime.utcnow(),
    }


@router.get("/activity/timeline", response_model=ActivityTimelineResponse)
@role_required(["admin", "security_analyst"])
async def get_activity_timeline(
    resolution: str = "1h",
    current_user: Dict = Depends(JWTBearer()),
    db: Session = Depends(get_db),
):
    """
    Get timeline of security events
    """
    resolutions = {
        "1m": "1 minute",
        "5m": "5 minutes",
        "15m": "15 minutes",
        "1h": "1 hour",
        "1d": "1 day",
    }

    if resolution not in resolutions:
        raise HTTPException(status_code=400, detail="Invalid resolution")

    # Get threats timeline
    threat_timeline = db.execute(
        f"""
        SELECT 
            date_trunc('{resolutions[resolution]}', timestamp) as time_bucket,
            threat_type,
            COUNT(*) as count
        FROM network_logs
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY time_bucket, threat_type
        ORDER BY time_bucket
        """
    ).fetchall()

    # Get firewall actions timeline
    firewall_timeline = db.execute(
        f"""
        SELECT 
            date_trunc('{resolutions[resolution]}', timestamp) as time_bucket,
            action,
            COUNT(*) as count
        FROM firewall_logs
        WHERE timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY time_bucket, action
        ORDER BY time_bucket
        """
    ).fetchall()

    return {
        "resolution": resolution,
        "threat_timeline": [
            {"time": t.time_bucket, "threat_type": t.threat_type, "count": t.count}
            for t in threat_timeline
        ],
        "firewall_timeline": [
            {"time": f.time_bucket, "action": f.action, "count": f.count}
            for f in firewall_timeline
        ],
    }
