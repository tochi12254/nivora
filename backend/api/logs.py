from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from typing import List, Dict
from datetime import datetime, timedelta

from app.database import get_db
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_
from models.log import NetworkLog
from models.firewall import FirewallLog

router = APIRouter()


@router.get("/network", response_model=List[Dict])
async def get_network_logs(
    db: Session = Depends(get_db),
    limit: int = 100,
    search: str = None,
    time_range: str = "24h",
):
    """Get network logs with search and filtering"""
    query = db.query(NetworkLog).order_by(desc(NetworkLog.timestamp))

    # Apply time range filter
    if time_range == "1h":
        time_filter = datetime.utcnow() - timedelta(hours=1)
    elif time_range == "24h":
        time_filter = datetime.utcnow() - timedelta(hours=24)
    elif time_range == "7d":
        time_filter = datetime.utcnow() - timedelta(days=7)
    else:
        time_filter = datetime.utcnow() - timedelta(hours=24)

    query = query.filter(NetworkLog.timestamp >= time_filter)

    # Apply search filter if provided
    if search:
        query = query.filter(
            or_(
                NetworkLog.threat_type.ilike(f"%{search}%"),
                NetworkLog.source_ip.ilike(f"%{search}%"),
                NetworkLog.destination_ip.ilike(f"%{search}%"),
                NetworkLog.protocol.ilike(f"%{search}%"),
            )
        )

    logs = query.limit(limit).all()

    return [
        {
            "timestamp": log.timestamp.isoformat(),
            "type": "threat",
            "threat_type": log.threat_type,
            "source_ip": log.source_ip,
            "destination_ip": log.destination_ip,
            "protocol": log.protocol,
            "details": (
                log.raw_data[:200] + "..." if len(log.raw_data) > 200 else log.raw_data
            ),
        }
        for log in logs
    ]


@router.get("/firewall", response_model=List[Dict])
async def get_firewall_logs(
    db: Session = Depends(get_db),
    limit: int = 100,
    search: str = None,
    time_range: str = "24h",
):
    """Get firewall logs with search and filtering"""
    query = db.query(FirewallLog).order_by(desc(FirewallLog.timestamp))

    # Apply time range filter
    if time_range == "1h":
        time_filter = datetime.utcnow() - timedelta(hours=1)
    elif time_range == "24h":
        time_filter = datetime.utcnow() - timedelta(hours=24)
    elif time_range == "7d":
        time_filter = datetime.utcnow() - timedelta(days=7)
    else:
        time_filter = datetime.utcnow() - timedelta(hours=24)

    query = query.filter(FirewallLog.timestamp >= time_filter)

    # Apply search filter if provided
    if search:
        query = query.filter(
            or_(
                FirewallLog.action.ilike(f"%{search}%"),
                FirewallLog.source_ip.ilike(f"%{search}%"),
                FirewallLog.destination_ip.ilike(f"%{search}%"),
                FirewallLog.protocol.ilike(f"%{search}%"),
            )
        )

    logs = query.limit(limit).all()

    return [
        {
            "timestamp": log.timestamp.isoformat(),
            "type": "firewall",
            "action": log.action,
            "source_ip": log.source_ip,
            "destination_ip": log.destination_ip,
            "protocol": log.protocol,
            "rule_id": log.rule_id,
        }
        for log in logs
    ]


@router.get("/combined", response_model=List[Dict])
async def get_combined_logs(
    db: Session = Depends(get_db), limit: int = 100, time_range: str = "24h"
):
    """Get combined network and firewall logs"""
    time_filter = datetime.utcnow() - timedelta(hours=24)  # Default 24h

    # Get network logs
    network_logs = (
        db.query(NetworkLog)
        .filter(NetworkLog.timestamp >= time_filter)
        .order_by(desc(NetworkLog.timestamp))
        .limit(limit)
        .all()
    )

    # Get firewall logs
    firewall_logs = (
        db.query(FirewallLog)
        .filter(FirewallLog.timestamp >= time_filter)
        .order_by(desc(FirewallLog.timestamp))
        .limit(limit)
        .all()
    )

    # Combine and sort
    combined = [
        {
            "timestamp": log.timestamp.isoformat(),
            "type": "threat",
            "event_type": log.threat_type,
            "source_ip": log.source_ip,
            "destination_ip": log.destination_ip,
            "protocol": log.protocol,
        }
        for log in network_logs
    ] + [
        {
            "timestamp": log.timestamp.isoformat(),
            "type": "firewall",
            "event_type": log.action,
            "source_ip": log.source_ip,
            "destination_ip": log.destination_ip,
            "protocol": log.protocol,
        }
        for log in firewall_logs
    ]

    # Sort by timestamp
    combined.sort(key=lambda x: x["timestamp"], reverse=True)

    return combined[:limit]
