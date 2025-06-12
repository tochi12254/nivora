# loader.py

import os
import sys
import asyncio
from dotenv import load_dotenv
from uvicorn import Config, Server

# Handle PyInstaller frozen executable paths
if getattr(sys, 'frozen', False):
    base_dir = sys._MEIPASS
else:
    base_dir = os.path.dirname(__file__)

# Load environment variables from .env
dotenv_path = os.path.join(base_dir, ".env")
load_dotenv(dotenv_path)

# Import after dotenv (to ensure env vars are available)
from main import create_app, emit_progress, mark_server_ready  # adjust if needed

async def run():
    app = await create_app()

    config = Config(
        app=app,
        host="127.0.0.1",
        port=8000,
        reload=False,
        workers=1,
        loop="asyncio",  # use "asyncio" to avoid uvloop dependency
        http="httptools",  # fast HTTP parser, safe to use
        log_level="info",
    )

    server = Server(config)

    # Run tasks concurrently
    server_task = asyncio.create_task(server.serve())
    asyncio.create_task(emit_progress())  # Optional async background task
    await mark_server_ready()            # Optional readiness marker
    await server_task

if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support() 
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nServer stopped by user.")
