# app/db_init.py
from app.database import engine
from app.models.user import User
from app.models.log import Log
from app.models.network import NetworkEvent
from app.models.threat import ThreatLog
import logging

logger = logging.getLogger(__name__)


def init_db():
    try:
        from app.models.base import Base

        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise
