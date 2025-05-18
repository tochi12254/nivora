# backend/app/database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import logging

logger = logging.getLogger(__name__)

SQLALCHEMY_DATABASE_URL = "sqlite:///./cyberwatch.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def init_db():
    """Initialize the database, create all tables if they don't exist"""
    from app.models.user import User
    from app.models.network import NetworkEvent
    from app.models.threat import ThreatLog
    from app.models.system import SystemLog
    from app.models.config import AppConfig

    try:
        logger.info("Creating database tables if they don't exist...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {str(e)}")
        raise


def get_db():
    """Database session dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
