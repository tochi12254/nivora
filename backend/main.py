from contextlib import asynccontextmanager
from datetime import datetime
import asyncio
import logging
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socketio
from multiprocessing import Queue, Manager 
from multiprocessing.queues import Full, Empty
import asyncio

# Configuration
from app.core.config import settings
from app.middleware.blocker_middleware import BlocklistMiddleware
from app.services.prevention.app_blocker import ApplicationBlocker
from app.core.logger import setup_logger
from socket_events import get_socket_app
from app.services.system.monitor import SystemMonitor
from app.services.detection.phishing_blocker import PhishingBlocker


# Database
from sqlalchemy.ext.asyncio import AsyncEngine
from app.database import engine, Base, AsyncSessionLocal, init_db


# Routers
from app.api import (
    users as user_router,
    network as network_router,
    auth as auth_router,
    threats as threat_router,
    system as system_router,
    admin as admin_router,
    ids as ids_router,
    ips as ips_router,
)
from app.api.ips import get_ips_engine

# Services
from app.services.monitoring.sniffer import PacketSniffer
from app.services.detection.signature import SignatureEngine
from app.services.detection.ids_signature import IdsSignatureEngine
from app.services.ips.engine import IPSEngine
from app.services.ips.adapter import IPSPacketAdapter
from app.services.prevention.firewall import FirewallManager
from app.services.tasks.autofill_task import run_autofill_task

# Socket.IO
from sio_instance import sio
from packet_sniffer_service import PacketSnifferService
from packet_sniffer_events import PacketSnifferNamespace

from socket_events import start_event_emitter, emit_ips_updates

# Logging setup
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
setup_logger("main", "INFO")
logger = logging.getLogger(__name__)

###VULNERABILITY
# scanner = VulnerabilityScanner(sio)
# val_blocker = ThreatBlocker(sio)


async def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    # Initialize FastAPI app first
    app = FastAPI(
        title=settings.PROJECT_NAME,
        docs_url="/api/docs" if settings.DOCS else None,
        redoc_url=None,
    )

    # Initialize database
    try:
        if isinstance(engine, AsyncEngine):
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database initialized successfully")
        else:
            raise RuntimeError("Database engine is not asynchronous")
    except Exception as e:
        logger.critical(f"Database initialization failed: {str(e)}")
        raise

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Lifespan for startup and shutdown events."""
        await init_db()
        logger.info("🚀 Starting CyberWatch Security System")
        logger.info("Initializing background services...")

        # Initialize services
        firewall = FirewallManager(sio)
        signature_engine = SignatureEngine(sio)
        ids_signature_engine = IdsSignatureEngine(sio)
        blocker = ApplicationBlocker(sio)
        ips_engine = IPSEngine(sio, blocker)
        # loop = asyncio.get_event_loop()  # Get current loop
        monitor = SystemMonitor(sio)

        # phishing_blocker = PhishingBlocker(sio)

        await ips_engine.initialize()

        # Initialize IPS Adapter
        ips_adapter = IPSPacketAdapter(ips_engine)
        await ips_adapter.start()

        # Start database autofill task
        autofill_task = asyncio.create_task(run_autofill_task(interval=300))

        # Store services in app state

        app.state.firewall = firewall
        app.state.signature_engine = signature_engine
        app.state.ids_signature_engine = ids_signature_engine
        app.state.ips_engine = ips_engine
        app.state.ips_adapter = ips_adapter
        app.state.db = AsyncSessionLocal
        app.state.autofill_task = autofill_task
        app.state.blocker = blocker

        emitter_task = asyncio.create_task(start_event_emitter())  # Pass the factory
        app.state.emitter_task = emitter_task

        # Initialize packet components INDEPENDENTLY
        manager = Manager()
        sio_queue = manager.Queue(maxsize=10000)
        sniffer_namespace = PacketSnifferNamespace('/packet_sniffer', sio_queue)
        sio.register_namespace(sniffer_namespace)

        sniffer = PacketSniffer(sio_queue)

        sniffer_service = PacketSnifferService(sio, sio_queue)

        try:
            await sniffer_service.start()
            sniffer.start("Wi-Fi")
            monitor.start()
            logger.info("System monitoring started")
            # Start packet sniffer with IPS integration

            # Start IPS updates task
            asyncio.create_task(ips_updates_task(ips_engine))

            yield

        finally:
            # Shutdown tasks
            logger.info("🛑 Gracefully shutting down...")

            if monitor:
                await monitor.stop()
            if sniffer:
                sniffer.stop()
            # if sniffer_service:
            #     await sniffer_service.stop()

            await ips_adapter.stop()
            autofill_task.cancel()
            await engine.dispose()

            emitter_task.cancel()
            # scanner.stop_silent_monitor()

            try:
                await emitter_task
            except asyncio.CancelledError:
                logger.info("Background tasks stopped")

            try:
                await autofill_task
            except asyncio.CancelledError:
                pass

    async def ips_updates_task(ips_engine: IPSEngine):
        """Background task for IPS updates"""
        while True:
            try:
                async with AsyncSessionLocal() as db:
                    await emit_ips_updates()
                    await asyncio.sleep(60)
            except Exception as e:
                logger.error(f"Error in IPS updates: {e}")
                await asyncio.sleep(5)

    # Set the lifespan after app creation
    app.router.lifespan_context = lifespan

    # Configure CORS first to ensure frontend access
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add other middlewares
    # app.add_middleware(HTTPSRedirectMiddleware)
    app.add_middleware(
        BlocklistMiddleware,
        blocker=(
            app.state.blocker
            if hasattr(app.state, "blocker")
            else ApplicationBlocker(sio)
        ),
    )

    # Register routers
    app.include_router(user_router.router, prefix="/api/users", tags=["Users"])
    app.include_router(network_router.router, prefix="/api/network", tags=["Network"])
    app.include_router(auth_router.router, prefix="/api/auth", tags=["Auth"])
    app.include_router(threat_router.router, prefix="/api/threats", tags=["Threats"])
    app.include_router(system_router.router, prefix="/api/system", tags=["System"])
    app.include_router(admin_router.router, prefix="/api/admin", tags=["Admin"])
    app.include_router(ids_router.router, prefix="/api/ids", tags=["IDS"])
    app.include_router(ips_router.router, prefix="/api/ips", tags=["IPS"])

    # Health check endpoint
    @app.get("/api/health", include_in_schema=False)
    async def health_check():
        return {"status": "ok"}

    # Mount Socket.IO app
    socket_app = get_socket_app(app)
    app.mount("/socket.io", socket_app)

    return app


# Socket.IO events
@sio.event
async def connect(sid, environ):
    logger.info(f"Client connected: {sid[:8]}...")


@sio.event
async def disconnect(sid):
    logger.info(f"Client disconnected: {sid[:8]}...")


# Hypercorn entry point
if __name__ == "__main__":
    import hypercorn.asyncio
    from hypercorn.config import Config

    config = Config()
    config.bind = ["127.0.0.1:8000"]
    config.use_reloader = True

    async def run():
        app = await create_app()  # Properly await the app creation
        await hypercorn.asyncio.serve(app, config)

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
