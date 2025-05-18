from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from typing import List, Dict
from datetime import datetime, timedelta

from services.prevention.firewall import PyFirewall
from models.firewall import FirewallRule, FirewallLog
from app.database import get_db
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database import get_db

from app.dependencies import get_firewall

router = APIRouter()
firewall = PyFirewall()


@router.on_event("startup")
async def startup_event():
    firewall = get_firewall()
    await firewall.initialize()


@router.get("/rules")
async def get_rules(firewall: PyFirewall = Depends(get_firewall)):
    return firewall.get_rules()


@router.get("/items")
async def read_items(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Item))
    return result.scalars().all()


@router.get("/rules", response_model=List[Dict])
async def get_firewall_rules(db: Session = Depends(get_db)):
    """Get all firewall rules"""
    return firewall.get_rules()


@router.post("/rules")
async def add_firewall_rule(rule: Dict):
    """Add a new firewall rule"""
    required_fields = ["action", "direction"]
    if not all(field in rule for field in required_fields):
        raise HTTPException(
            status_code=400, detail="Missing required fields: action, direction"
        )

    if firewall.add_rule(rule):
        return JSONResponse(
            content={"status": "success", "message": "Rule added successfully"},
            status_code=201,
        )
    else:
        raise HTTPException(status_code=400, detail="Failed to add firewall rule")


@router.post("/block-ip")
async def block_ip_address(ip: str, timeout: int = None):
    """Block an IP address temporarily or permanently"""
    if firewall.block_ip(ip, timeout):
        return {"status": "success", "message": f"IP {ip} blocked"}
    else:
        raise HTTPException(status_code=400, detail=f"Failed to block IP {ip}")


@router.get("/logs", response_model=List[Dict])
async def get_firewall_logs(
    db: Session = Depends(get_db),
    limit: int = 100,
    action: str = None,
    time_range: str = "24h",
):
    """Get firewall logs with filtering options"""
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

    # Apply action filter if provided
    if action:
        query = query.filter(FirewallLog.action == action)

    logs = query.limit(limit).all()

    return [
        {
            "timestamp": log.timestamp.isoformat(),
            "action": log.action,
            "source_ip": log.source_ip,
            "destination_ip": log.destination_ip,
            "protocol": log.protocol,
            "rule_id": log.rule_id,
        }
        for log in logs
    ]
