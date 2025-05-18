from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List, Optional, Dict
from app.database import get_db
from models.log import NetworkLog
from services.detection.signature import SignatureEngine
from schemas.ids import (
    IDSConfigResponse,
    IDSRuleCreate,
    IDSRuleResponse,
    IDSThreatResponse,
    IDSStatsResponse,
)
from app.utils.security import JWTBearer, role_required
from app.utils.monitoring import track_function_metrics

router = APIRouter(tags=["IDS"])


@router.get("/config", response_model=IDSConfigResponse)
@role_required(["admin", "security_analyst"])
@track_function_metrics("ids_get_config")
async def get_ids_config(
    current_user: Dict = Depends(JWTBearer()),
    signature_engine: SignatureEngine = Depends(SignatureEngine),
):
    """
    Get current IDS configuration
    """
    return {
        "rule_count": len(signature_engine.rules),
        "enabled": True,  # Would come from config
        "last_updated": datetime.utcnow(),
        "signature_sources": ["built-in", "custom"],
        "performance": {
            "avg_processing_time": 0.05,  # Would be calculated
            "throughput": 1000,  # packets/sec
        },
    }


@router.get("/rules", response_model=List[IDSRuleResponse])
@role_required(["admin", "security_analyst"])
@track_function_metrics("ids_list_rules")
async def list_ids_rules(
    current_user: Dict = Depends(JWTBearer()),
    signature_engine: SignatureEngine = Depends(SignatureEngine),
):
    """
    List all IDS rules
    """
    return signature_engine.get_rules()


@router.post("/rules", response_model=IDSRuleResponse, status_code=201)
@role_required(["admin", "security_engineer"])
@track_function_metrics("ids_create_rule")
async def create_ids_rule(
    rule: IDSRuleCreate,
    current_user: Dict = Depends(JWTBearer()),
    signature_engine: SignatureEngine = Depends(SignatureEngine),
):
    """
    Create a new IDS rule
    """
    success = signature_engine.add_rule(rule.dict())
    if not success:
        raise HTTPException(status_code=400, detail="Failed to add rule")

    return rule


@router.get("/threats", response_model=List[IDSThreatResponse])
@role_required(["admin", "security_analyst"])
@track_function_metrics("ids_list_threats")
async def list_ids_threats(
    time_range: str = "24h",
    severity: Optional[str] = None,
    current_user: Dict = Depends(JWTBearer()),
    db: Session = Depends(get_db),
):
    """
    List threats detected by IDS
    """
    time_map = {
        "1h": timedelta(hours=1),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }

    delta = time_map.get(time_range, timedelta(hours=24))
    since = datetime.utcnow() - delta

    query = db.query(NetworkLog).filter(NetworkLog.timestamp >= since)

    if severity:
        query = query.filter(NetworkLog.threat_type.ilike(f"%{severity}%"))

    threats = query.order_by(NetworkLog.timestamp.desc()).limit(1000).all()

    return [
        {
            "id": t.id,
            "timestamp": t.timestamp,
            "threat_type": t.threat_type,
            "source_ip": t.source_ip,
            "destination_ip": t.destination_ip,
            "protocol": t.protocol,
            "length": t.length,
        }
        for t in threats
    ]


@router.get("/stats", response_model=IDSStatsResponse)
@role_required(["admin", "security_analyst"])
@track_function_metrics("ids_get_stats")
async def get_ids_stats(
    time_range: str = "24h",
    current_user: Dict = Depends(JWTBearer()),
    db: Session = Depends(get_db),
):
    """
    Get IDS statistics
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
    threat_counts = db.execute(
        """
        SELECT 
            threat_type,
            COUNT(*) as count
        FROM network_logs
        WHERE timestamp >= :since
        GROUP BY threat_type
        ORDER BY count DESC
        """,
        {"since": since},
    ).fetchall()

    # Top source IPs
    top_sources = db.execute(
        """
        SELECT 
            source_ip,
            COUNT(*) as count
        FROM network_logs
        WHERE timestamp >= :since
        AND source_ip IS NOT NULL
        GROUP BY source_ip
        ORDER BY count DESC
        LIMIT 10
        """,
        {"since": since},
    ).fetchall()

    # Threat timeline
    timeline = db.execute(
        """
        SELECT 
            DATE_TRUNC('hour', timestamp) as hour,
            COUNT(*) as count
        FROM network_logs
        WHERE timestamp >= :since
        GROUP BY hour
        ORDER BY hour
        """,
        {"since": since},
    ).fetchall()

    return {
        "time_range": time_range,
        "total_threats": sum(t.count for t in threat_counts),
        "threats_by_type": {t.threat_type: t.count for t in threat_counts},
        "top_source_ips": [{"ip": t.source_ip, "count": t.count} for t in top_sources],
        "timeline": [{"time": t.hour, "count": t.count} for t in timeline],
        "start_time": since,
        "end_time": datetime.utcnow(),
    }
