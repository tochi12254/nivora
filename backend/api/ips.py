from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List, Optional, Dict
from ipaddress import ip_network

from app.database import get_db
from models.firewall import FirewallRule, FirewallLog
from services.prevention.firewall import PyFirewall
from schemas.ips import (
    IPSConfigResponse,
    IPSActionResponse,
    IPSBlockIPRequest,
    IPSRuleResponse,
    IPSStatsResponse,
    IPSTopThreatsResponse,
)
from app.utils.security import JWTBearer, role_required
from app.utils.monitoring import track_function_metrics

router = APIRouter(tags=["IPS"])


@router.get("/config", response_model=IPSConfigResponse)
@role_required(["admin", "security_analyst"])
@track_function_metrics("ips_get_config")
async def get_ips_config(
    current_user: Dict = Depends(JWTBearer()),
    firewall: PyFirewall = Depends(PyFirewall),
):
    """
    Get current IPS configuration
    """
    return {
        "enabled": True,
        "mode": "prevention",  # or "detection"
        "default_action": "block",
        "rule_count": len(firewall.rules),
        "last_updated": datetime.utcnow(),
    }


@router.post("/actions/block", response_model=IPSActionResponse)
@role_required(["admin", "security_engineer"])
@track_function_metrics("ips_block_ip")
async def block_ip_address(
    request: IPSBlockIPRequest,
    current_user: Dict = Depends(JWTBearer()),
    firewall: PyFirewall = Depends(PyFirewall),
):
    """
    Block an IP address
    """
    try:
        # Validate IP address
        ip_network(request.ip_address)

        success = firewall.block_ip(request.ip_address, request.duration_seconds)
        if not success:
            raise HTTPException(status_code=400, detail="Failed to block IP")

        return {
            "action": "block",
            "target": request.ip_address,
            "duration": request.duration_seconds,
            "status": "success",
            "timestamp": datetime.utcnow(),
        }
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")


@router.post("/actions/unblock")
@role_required(["admin", "security_engineer"])
@track_function_metrics("ips_unblock_ip")
async def unblock_ip_address(
    ip_address: str,
    current_user: Dict = Depends(JWTBearer()),
    db: Session = Depends(get_db),
):
    """
    Unblock an IP address
    """
    try:
        # Validate IP address
        ip_network(ip_address)

        # Find and disable blocking rules
        rules = (
            db.query(FirewallRule)
            .filter(
                FirewallRule.source_ip == ip_address,
                FirewallRule.action == "deny",
                FirewallRule.is_active == True,
            )
            .all()
        )

        if not rules:
            return {"status": "success", "message": "No active blocks found"}

        for rule in rules:
            rule.is_active = False
            rule.updated_at = datetime.utcnow()
            rule.updated_by = current_user.get("sub")

        db.commit()

        return {
            "action": "unblock",
            "target": ip_address,
            "status": "success",
            "rules_modified": len(rules),
            "timestamp": datetime.utcnow(),
        }
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")


@router.get("/rules", response_model=List[IPSRuleResponse])
@role_required(["admin", "security_analyst"])
@track_function_metrics("ips_list_rules")
async def list_ips_rules(
    current_user: Dict = Depends(JWTBearer()),
    firewall: PyFirewall = Depends(PyFirewall),
):
    """
    List all IPS rules
    """
    return firewall.get_rules()


@router.get("/stats", response_model=IPSStatsResponse)
@role_required(["admin", "security_analyst"])
@track_function_metrics("ips_get_stats")
async def get_ips_stats(
    time_range: str = "24h",
    current_user: Dict = Depends(JWTBearer()),
    db: Session = Depends(get_db),
):
    """
    Get IPS statistics
    """
    time_map = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }

    delta = time_map.get(time_range, timedelta(hours=24))
    since = datetime.utcnow() - delta

    # Action counts
    action_counts = db.execute(
        """
        SELECT 
            action,
            COUNT(*) as count
        FROM firewall_logs
        WHERE timestamp >= :since
        GROUP BY action
        ORDER BY count DESC
        """,
        {"since": since},
    ).fetchall()

    # Top blocked IPs
    top_blocked = db.execute(
        """
        SELECT 
            source_ip,
            COUNT(*) as count
        FROM firewall_logs
        WHERE timestamp >= :since
        AND action = 'deny'
        AND source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT 10
        """,
        {"since": since},
    ).fetchall()

    return {
        "time_range": time_range,
        "total_actions": sum(a.count for a in action_counts),
        "actions_by_type": {a.action: a.count for a in action_counts},
        "top_blocked_ips": [{"ip": t.source_ip, "count": t.count} for t in top_blocked],
        "start_time": since,
        "end_time": datetime.utcnow(),
    }


@router.get("/threats/top", response_model=List[IPSTopThreatsResponse])
@role_required(["admin", "security_analyst"])
@track_function_metrics("ips_top_threats")
async def get_top_threats(
    limit: int = 10,
    current_user: Dict = Depends(JWTBearer()),
    db: Session = Depends(get_db),
):
    """
    Get top threats prevented by IPS
    """
    threats = db.execute(
        """
        SELECT 
            fl.source_ip,
            nl.threat_type,
            COUNT(*) as count
        FROM firewall_logs fl
        JOIN network_logs nl ON fl.source_ip = nl.source_ip
        WHERE fl.action = 'deny'
        AND fl.timestamp >= NOW() - INTERVAL '24 hours'
        GROUP BY fl.source_ip, nl.threat_type
        ORDER BY count DESC
        LIMIT :limit
        """,
        {"limit": limit},
    ).fetchall()

    return [
        {"source_ip": t.source_ip, "threat_type": t.threat_type, "count": t.count}
        for t in threats
    ]
