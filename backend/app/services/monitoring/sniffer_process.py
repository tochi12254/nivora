# sniffer_process.py

import asyncio
from multiprocessing import Queue
from .packet import PacketSniffer
from ...core.config import settings


# sniffer_process.py (continued)


def run_sniffer(sio, control_queue: Queue):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    sniffer = PacketSniffer(sio, loop)

    # Start the sniffer
    sniffer.start(settings.NETWORK_INTERFACE)

    async def monitor_control_queue():
        while True:
            if not control_queue.empty():
                command = control_queue.get()
                if command == "stop":
                    await sniffer.stop()
                    break
            await asyncio.sleep(1)

    loop.create_task(monitor_control_queue())

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(sniffer.stop())
        loop.close()
