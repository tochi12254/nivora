from fastapi import APIRouter, Depends
from app.services.monitoring.packet import PacketSniffer

router = APIRouter()


@router.get("/stats")
async def get_system_stats(sniffer: PacketSniffer = Depends()):
    return sniffer.get_stats()
