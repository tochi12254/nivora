# reporter.py

import time
from datetime import datetime
from collections.abc import Mapping, Iterable
from multiprocessing.managers import DictProxy, ListProxy
from multiprocessing import Event



def _serialize(obj):
    """
    Recursively convert unsupported types into JSON-serializable structures:
    - datetime → ISO8601 string
    - Manager proxies (DictProxy, ListProxy) → dict/list
    - other Mapping/Iterable → recurse
    """
    if isinstance(obj, datetime):
        return obj.isoformat()

    # First: convert proxies to their native types and recurse
    if isinstance(obj, DictProxy):
        return {k: _serialize(v) for k, v in dict(obj).items()}
    if isinstance(obj, ListProxy):
        return [_serialize(v) for v in list(obj)]

    # Then: handle any other Mapping or Iterable
    if isinstance(obj, Mapping):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, Iterable) and not isinstance(obj, (str, bytes)):
        return [_serialize(v) for v in obj]

    # Return primitive
    return obj


def _reporter_loop(sio_queue, stats_proxy, stop_event, interval: float = 5.0):
    """
    Runs in its own Process. Periodically snapshots `stats_proxy`
    (a Manager().dict proxy), serializes it, and pushes to sio_queue.
    """
    while not stop_event.is_set():
        try:
            # make a shallow copy of the current stats
            snapshot = dict(stats_proxy)

            # convert datetimes and proxies into JSON-safe types
            serialized_snapshot = _serialize(snapshot)

            # enqueue for the socket-emitter service
            sio_queue.put(("system_stats", serialized_snapshot))
        except Exception as e:
            # no logger in child; fall back to print
            print("Reporter loop error:", e)

        # wait up to `interval` seconds, but wake early if stop_event is set
        stop_event.wait(interval)
