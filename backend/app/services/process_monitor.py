import psutil
import hashlib
import socket
import asyncio
from datetime import datetime
import json
from typing import Dict, List
import socketio
from ..models.process import ProcessActivity

class ProcessMonitor:
    def __init__(self, sio: socketio.AsyncServer, db_session, interval=30):
        self.sio = sio
        self.db = db_session
        self.interval = interval
        self.hostname = socket.gethostname()
        self.baseline_processes = set()
        self.running = False

    async def start(self):
        """Start periodic process monitoring"""
        self.running = True
        while self.running:
            try:
                processes = self._collect_process_data()
                await self._analyze_processes(processes)
                await asyncio.sleep(self.interval)
            except Exception as e:
                print(f"Process monitoring error: {e}")
                await asyncio.sleep(5)  # Wait before retry

    def _collect_process_data(self) -> List[Dict]:
        """Collect detailed process information"""
        processes = []
        for proc in psutil.process_iter(
            [
                "pid",
                "ppid",
                "name",
                "exe",
                "cmdline",
                "username",
                "cpu_percent",
                "memory_percent",
                "num_threads",
                "status",
                "create_time",
            ]
        ):
            try:
                proc_info = proc.info

                # Get network connections
                connections = []
                for conn in proc.connections(kind="inet"):
                    connections.append(
                        {
                            "fd": conn.fd,
                            "family": conn.family,
                            "type": conn.type,
                            "local_addr": conn.laddr,
                            "remote_addr": conn.raddr,
                            "status": conn.status,
                        }
                    )

                # Calculate file hashes
                hashes = {}
                if proc_info["exe"]:
                    try:
                        with open(proc_info["exe"], "rb") as f:
                            file_data = f.read()
                            hashes["md5"] = hashlib.md5(file_data).hexdigest()
                            hashes["sha1"] = hashlib.sha1(file_data).hexdigest()
                            hashes["sha256"] = hashlib.sha256(file_data).hexdigest()
                    except (PermissionError, FileNotFoundError):
                        pass

                processes.append(
                    {
                        "pid": proc_info["pid"],
                        "ppid": proc_info["ppid"],
                        "name": proc_info["name"],
                        "exe_path": proc_info["exe"],
                        "cmdline": (
                            " ".join(proc_info["cmdline"])
                            if proc_info["cmdline"]
                            else None
                        ),
                        "username": proc_info["username"],
                        "cpu_percent": proc_info["cpu_percent"],
                        "memory_percent": proc_info["memory_percent"],
                        "num_threads": proc_info["num_threads"],
                        "status": proc_info["status"],
                        "create_time": proc_info["create_time"],
                        "connections": connections,
                        "hashes": hashes,
                        "hostname": self.hostname,
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes

    async def _analyze_processes(self, processes: List[Dict]):
        """Analyze processes for anomalies and malware indicators"""
        current_pids = {p["pid"] for p in processes}

        # Detect process anomalies
        for proc in processes:
            # Example UEBA detection - customize with your rules
            anomaly_score = 0.0
            indicators = []

            # High CPU usage detection
            if proc["cpu_percent"] > 90:
                anomaly_score += 30
                indicators.append("high_cpu_usage")

            # Unusual parent-child relationship
            if proc["ppid"] == 1 and proc["name"] not in ["systemd", "init"]:
                anomaly_score += 40
                indicators.append("unusual_parent_process")

            # Unsigned binary detection
            if not proc["hashes"] and proc["exe_path"]:
                anomaly_score += 50
                indicators.append("unsigned_binary")

            # Add process to database
            proc["anomaly_score"] = anomaly_score
            db_proc = ProcessActivity(**proc)
            self.db.add(db_proc)
            await self.db.commit()

            # Emit alerts if thresholds exceeded
            if anomaly_score > 70:
                await self.sio.emit(
                    "process_alert",
                    {
                        "process": proc,
                        "alert_type": "suspicious_behavior",
                        "confidence": min(100, anomaly_score),
                        "indicators": indicators,
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                )

        # Detect terminated processes (for baseline comparison)
        terminated = self.baseline_processes - current_pids
        if terminated:
            await self.sio.emit(
                "process_terminated",
                {"pids": list(terminated), "timestamp": datetime.utcnow().isoformat()},
            )

        self.baseline_processes = current_pids
