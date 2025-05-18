import asyncio
import os
import platform
import psutil
import cpuinfo
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import socketio
from datetime import datetime
import hashlib
import threading
from typing import Dict, Any, List
import logging
import time
from collections import deque

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SystemMonitor")


class SystemMonitor:

    def __init__(self, sio: socketio.AsyncServer, loop: asyncio.AbstractEventLoop):
        self.sio = sio
        self.loop = loop  # Store the event loop
        self.observer = Observer()
        self.should_run = False  # Control flag
        self.file_hashes = {}  # Track file integrity
        self.baselines = self._init_baselines()
        self.sensitive_keywords = ["confidential", "password", "budget"]
        self.history = {
            "cpu": deque(maxlen=60),
            "memory": deque(maxlen=60),
            "network": deque(maxlen=60),
            "disk": deque(maxlen=60),
        }
        self.anomaly_thresholds = {
            "cpu": 90,  # %
            "memory": 90,  # %
            "disk": 90,  # %
            "network": 100000000,  # bytes/s
        }
        self.suspicious_processes = ["mimikatz", "powersploit", "cobaltstrike"]
        self.suspicious_ports = {4444: "Metasploit", 8080: "Webshell", 9999: "C2"}

    async def start(self):
        """Start monitoring services safely"""
        await asyncio.sleep(20)  # Let other services initialize first
        self.should_run = True
        asyncio.create_task(self._send_system_stats())
        await self._start_file_monitoring_async()

    def stop(self):
        """Stop all monitoring"""
        self.should_run = False
        if self.observer:
            self.observer.stop()
            self.observer.join()
        logger.info("System monitor stopped")

    async def start_with_delay(self, delay: float = 5.0):
        """Public method to start monitoring after a delay"""
        await asyncio.sleep(delay)
        await self.start()

    async def _send_system_stats(self):
        """Send comprehensive system telemetry every 5 seconds"""
        while True:
            try:
                stats = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "host_info": self._get_host_info(),
                    "processes": self._get_process_analytics(),
                    "network": self._get_network_analytics(),
                    "hardware": self._get_hardware_stats(),
                    "disk": self._get_disk_stats(),
                    "security": self._get_security_status(),
                    "performance": self._get_performance_metrics(),
                }

                # Update history
                self._update_history(stats)

                await self.sio.emit("system_telemetry", stats)

            except Exception as e:
                logger.error(f"Telemetry error: {e}")
            await asyncio.sleep(5)

    def _update_history(self, stats: Dict):
        """Update historical data for trend analysis"""
        self.history["cpu"].append(stats["hardware"]["cpu"]["total_usage"])
        self.history["memory"].append(stats["hardware"]["memory"]["percent"])

        net_stats = stats["network"]["bandwidth"]
        net_usage = (
            net_stats["bytes_sent"] + net_stats["bytes_recv"]
        ) / 5  # bytes per second
        self.history["network"].append(net_usage)

        disk_stats = stats["disk"]["partitions"][0]  # Primary partition
        self.history["disk"].append(disk_stats["usage_percent"])

    async def _check_for_anomalies(self):
        """Check for abnormal patterns in system metrics"""
        while True:
            try:
                alerts = []

                # Check CPU spikes
                if len(self.history["cpu"]) > 10:
                    avg_cpu = sum(self.history["cpu"]) / len(self.history["cpu"])
                    if avg_cpu > self.anomaly_thresholds["cpu"]:
                        alerts.append(
                            {
                                "type": "cpu",
                                "severity": "high",
                                "message": f"Sustained high CPU usage: {avg_cpu:.1f}%",
                            }
                        )

                # Check memory usage
                if len(self.history["memory"]) > 10:
                    avg_mem = sum(self.history["memory"]) / len(self.history["memory"])
                    if avg_mem > self.anomaly_thresholds["memory"]:
                        alerts.append(
                            {
                                "type": "memory",
                                "severity": "high",
                                "message": f"Sustained high memory usage: {avg_mem:.1f}%",
                            }
                        )

                # Check network activity
                if len(self.history["network"]) > 10:
                    avg_net = sum(self.history["network"]) / len(
                        self.history["network"]
                    )
                    if avg_net > self.anomaly_thresholds["network"]:
                        alerts.append(
                            {
                                "type": "network",
                                "severity": "medium",
                                "message": f"High network throughput: {avg_net/1000000:.2f} MB/s",
                            }
                        )

                if alerts:
                    await self.sio.emit(
                        "system_alerts",
                        {"timestamp": datetime.utcnow().isoformat(), "alerts": alerts},
                    )

            except Exception as e:
                logger.error(f"Anomaly detection error: {e}")

            await asyncio.sleep(30)  # Check every 30 seconds

    async def _start_file_monitoring_async(self):
        """Start file monitoring in a thread-safe way"""
        if self.observer is None:
            self.observer = Observer()
            event_handler = self._create_event_handler()
            self.observer.schedule(event_handler, path="/", recursive=True)

            # Run the observer in a separate thread
            def run_observer():
                try:
                    self.observer.start()
                    while self.should_run:
                        time.sleep(1)
                except Exception as e:
                    logger.error(f"Observer error: {e}")
                finally:
                    if self.observer:
                        self.observer.stop()
                        self.observer.join()

            threading.Thread(target=run_observer, daemon=True).start()

    def _create_event_handler(self):
        """Create the event handler with proper async bridge"""

        class SecurityEventHandler(FileSystemEventHandler):
            def __init__(self, monitor):
                self.monitor = monitor

            def on_modified(self, event):
                if not event.is_directory:
                    asyncio.run_coroutine_threadsafe(
                        self.monitor._analyze_file_event("modified", event.src_path),
                        self.monitor.loop,
                    )

            def on_created(self, event):
                """Handle file creation events"""
                if not event.is_directory:
                    asyncio.run_coroutine_threadsafe(
                        self.monitor._analyze_file_event("created", event.src_path),
                        self.monitor.loop,
                    )

            def on_deleted(self, event):
                """Handle file deletion events"""
                if not event.is_directory:
                    asyncio.run_coroutine_threadsafe(
                        self.monitor._analyze_file_event("deleted", event.src_path),
                        self.monitor.loop,
                    )

            def on_moved(self, event):
                """Handle file move/rename events"""
                if not event.is_directory:
                    asyncio.run_coroutine_threadsafe(
                        self.monitor._analyze_file_event(
                            "moved",
                            {"src_path": event.src_path, "dest_path": event.dest_path},
                        ),
                        self.monitor.loop,
                    )

            def on_closed(self, event):
                """Handle file close events (after writes)"""
                if not event.is_directory:
                    asyncio.run_coroutine_threadsafe(
                        self.monitor._analyze_file_event("closed", event.src_path),
                        self.monitor.loop,
                    )

            def on_opened(self, event):
                """Handle file open events"""
                if not event.is_directory:
                    asyncio.run_coroutine_threadsafe(
                        self.monitor._analyze_file_event("opened", event.src_path),
                        self.monitor.loop,
                    )

        return SecurityEventHandler(self)

    async def _analyze_file_event(self, event_type: str, path: str):
        """Rich file event analysis with threat scoring"""
        try:
            process = self._get_responsible_process()
            file_data = {
                "event_type": event_type,
                "path": path,
                "file_size": os.path.getsize(path) if os.path.exists(path) else 0,
                "file_name": os.path.basename(path),
                "file_extension": os.path.splitext(path)[1],
                "directory": os.path.dirname(path),
                "is_sensitive": any(
                    kw in path.lower() for kw in self.sensitive_keywords
                ),
                "timestamp": datetime.utcnow().isoformat(),
                "process_info": self._get_process_info(process) if process else None,
                "file_integrity": (
                    self._check_file_integrity(path)
                    if event_type != "deleted"
                    else None
                ),
                "security_context": self._get_security_context(path),
                "user_behavior": self._check_behavior_anomalies(),
                "alert": {},  # Populated later
            }

            # Threat analysis
            file_data["alert"] = self._assess_file_threat(file_data)

            await self.sio.emit("file_event", file_data)
        except Exception as e:
            logger.error(f"File analysis error for {path}: {e}")

    def _get_responsible_process(self) -> psutil.Process:
        """Get process responsible for current file operation"""
        # Cross-platform method to find process handling the file
        for proc in psutil.process_iter(["pid", "name", "open_files"]):
            try:
                if any(f.path == path for f in proc.open_files()):
                    return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None

    def _assess_file_threat(self, data: Dict) -> Dict:
        """Calculate risk score and generate alerts"""
        score = 0
        factors = []

        # Scoring logic
        if data["is_sensitive"]:
            score += 3
            factors.append("sensitive_file_accessed")

        if data["process_info"] and not data["process_info"]["is_signed_binary"]:
            score += 4
            factors.append("unsigned_process")

        if data["file_integrity"] and data["file_integrity"]["changed"]:
            score += 2
            factors.append("file_integrity_changed")

        if data["user_behavior"]["is_after_hours"]:
            score += 1
            factors.append("after_hours_activity")

        # Severity mapping
        severity = "low"
        if score >= 7:
            severity = "critical"
        elif score >= 5:
            severity = "high"
        elif score >= 3:
            severity = "medium"

        return {
            "risk_score": score,
            "severity": severity,
            "contributing_factors": factors,
            "suggested_actions": self._get_mitigation_actions(score),
        }

    def _get_mitigation_actions(self, score: int) -> List[str]:
        """Dynamic response recommendations"""
        if score >= 7:
            return ["Quarantine file", "Terminate process", "Alert SOC"]
        elif score >= 5:
            return ["Create backup", "Log process tree", "Notify admin"]
        return ["Monitor for further activity"]

    def _get_host_info(self) -> Dict:
        """Get system identification data"""
        return {
            "os": platform.system(),
            "os_version": platform.version(),
            "hostname": platform.node(),
            "user": os.getlogin(),
            "cpu": cpuinfo.get_cpu_info()["brand_raw"],
            "cores": {
                "physical": psutil.cpu_count(logical=False),
                "logical": psutil.cpu_count(logical=True),
            },
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            "uptime": time.time() - psutil.boot_time(),
            "python_version": platform.python_version(),
        }

    def _get_process_analytics(self) -> List[Dict]:
        """Analyze running processes with security context"""
        processes = []

        for proc in psutil.process_iter(
            [
                "pid",
                "name",
                "username",
                "cpu_percent",
                "memory_percent",
                "exe",
                "cmdline",
            ]
        ):
            try:
                proc_info = proc.info
                processes.append(
                    {
                        "pid": proc_info["pid"],
                        "name": proc_info["name"],
                        "user": proc_info["username"],
                        "cpu": proc_info["cpu_percent"],
                        "memory": proc_info["memory_percent"],
                        "command": (
                            " ".join(proc_info["cmdline"])
                            if proc_info["cmdline"]
                            else None
                        ),
                        "is_suspicious": any(
                            p in proc_info["name"].lower()
                            for p in self.suspicious_processes
                        ),
                        "is_signed": (
                            self._check_binary_signature(proc_info["exe"])
                            if proc_info["exe"]
                            else None
                        ),
                        "threads": proc.num_threads(),
                        "status": proc.status(),
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Sort by CPU usage
        processes.sort(key=lambda p: p["cpu"], reverse=True)
        return processes[:50]  # Return top 50 processes

    def _get_network_analytics(self) -> Dict:
        """Network connection analysis"""
        connections = []
        for conn in psutil.net_connections(kind="inet"):
            try:
                if conn.status == "ESTABLISHED":
                    connections.append(
                        {
                            "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "remote": (
                                f"{conn.raddr.ip}:{conn.raddr.port}"
                                if conn.raddr
                                else None
                            ),
                            "process": (
                                psutil.Process(conn.pid).name() if conn.pid else None
                            ),
                            "is_suspicious": self._is_suspicious_port(conn.laddr.port),
                            "status": conn.status,
                            "family": (
                                "IPv6" if conn.family.name == "AF_INET6" else "IPv4"
                            ),
                        }
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        io_counters = psutil.net_io_counters()
        return {
            "connections": connections,
            "bandwidth": {
                "bytes_sent": io_counters.bytes_sent,
                "bytes_recv": io_counters.bytes_recv,
                "packets_sent": io_counters.packets_sent,
                "packets_recv": io_counters.packets_recv,
                "error_in": io_counters.errin,
                "error_out": io_counters.errout,
                "drop_in": io_counters.dropin,
                "drop_out": io_counters.dropout,
            },
            "interfaces": self._get_network_interfaces(),
        }

    def _get_network_interfaces(self) -> List[Dict]:
        """Get detailed network interface information"""
        interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            stats = psutil.net_if_stats().get(name)
            interfaces.append(
                {
                    "name": name,
                    "addresses": [
                        {
                            "family": addr.family.name,
                            "address": addr.address,
                            "netmask": addr.netmask,
                            "broadcast": addr.broadcast,
                        }
                        for addr in addrs
                    ],
                    "is_up": stats.isup if stats else False,
                    "speed": stats.speed if stats else 0,
                    "mtu": stats.mtu if stats else 0,
                }
            )
        return interfaces

    def _get_hardware_stats(self) -> Dict:
        """Get comprehensive hardware statistics"""
        cpu_times = psutil.cpu_times_percent(interval=1)
        cpu_freq = psutil.cpu_freq()

        return {
            "cpu": {
                "total_usage": psutil.cpu_percent(interval=1),
                "per_core": psutil.cpu_percent(interval=1, percpu=True),
                "times": {
                    "user": cpu_times.user,
                    "system": cpu_times.system,
                    "idle": cpu_times.idle,
                    "iowait": getattr(cpu_times, "iowait", 0),
                    "irq": getattr(cpu_times, "irq", 0),
                    "softirq": getattr(cpu_times, "softirq", 0),
                },
                "frequency": {
                    "current": cpu_freq.current if cpu_freq else None,
                    "min": cpu_freq.min if cpu_freq else None,
                    "max": cpu_freq.max if cpu_freq else None,
                },
                "load_avg": os.getloadavg() if hasattr(os, "getloadavg") else None,
            },
            "memory": {
                "total": psutil.virtual_memory().total,
                "available": psutil.virtual_memory().available,
                "used": psutil.virtual_memory().used,
                "free": psutil.virtual_memory().free,
                "percent": psutil.virtual_memory().percent,
                "swap": {
                    "total": psutil.swap_memory().total,
                    "used": psutil.swap_memory().used,
                    "free": psutil.swap_memory().free,
                    "percent": psutil.swap_memory().percent,
                },
            },
            "temperatures": self._get_temperatures(),
            "fans": self._get_fan_speeds(),
            "battery": self._get_battery_info(),
        }

    def _get_disk_stats(self) -> Dict:
        """Get disk usage and IO statistics with robust error handling"""
        partitions = []
        for part in psutil.disk_partitions():
            try:
                # Skip CD/DVD drives and network drives that might not be ready
                if part.fstype in ("", "udf", "cdfs") or "cdrom" in part.opts:
                    continue

                usage = psutil.disk_usage(part.mountpoint)
                partitions.append(
                    {
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "opts": part.opts,
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "usage_percent": usage.percent,
                        "status": "active",
                    }
                )
            except Exception as e:
                logger.warning(
                    f"Error getting disk stats for {part.mountpoint}: {str(e)}"
                )
                partitions.append(
                    {
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "opts": part.opts,
                        "status": "unavailable",
                        "error": str(e),
                    }
                )

        try:
            io_counters = psutil.disk_io_counters()
            io_data = (
                {
                    "read_count": io_counters.read_count,
                    "write_count": io_counters.write_count,
                    "read_bytes": io_counters.read_bytes,
                    "write_bytes": io_counters.write_bytes,
                    "read_time": io_counters.read_time,
                    "write_time": io_counters.write_time,
                }
                if io_counters
                else None
            )
        except Exception as e:
            logger.warning(f"Error getting disk IO counters: {str(e)}")
            io_data = None

        return {"partitions": partitions, "io_counters": io_data}

    def _get_security_status(self) -> Dict:
        """Get security-related status information"""
        return {
            "suspicious_processes": len(
                [p for p in self._get_process_analytics() if p["is_suspicious"]]
            ),
            "suspicious_connections": len(
                [
                    c
                    for c in self._get_network_analytics()["connections"]
                    if c["is_suspicious"]
                ]
            ),
            "system_updates": self._check_system_updates(),
            "firewall_status": self._check_firewall_status(),
            "last_scan": datetime.utcnow().isoformat(),
        }

    def _get_performance_metrics(self) -> Dict:
        """Calculate performance metrics and scores"""
        cpu_usage = psutil.cpu_percent(interval=1)
        mem_usage = psutil.virtual_memory().percent
        disk_usage = max(
            [p["usage_percent"] for p in self._get_disk_stats()["partitions"]] or [0]
        )

        # Calculate performance score (0-100, higher is better)
        score = 100 - ((cpu_usage + mem_usage + disk_usage) / 3)

        return {
            "score": score,
            "cpu_usage": cpu_usage,
            "memory_usage": mem_usage,
            "disk_usage": disk_usage,
            "health_status": (
                "excellent"
                if score > 90
                else "good" if score > 70 else "fair" if score > 50 else "poor"
            ),
        }

    def _get_temperatures(self) -> Dict:
        """Get hardware temperatures if available"""
        try:
            temps = psutil.sensors_temperatures()
            return {
                name: [
                    {
                        "label": temp.label,
                        "current": temp.current,
                        "high": temp.high,
                        "critical": temp.critical,
                    }
                    for temp in entries
                ]
                for name, entries in temps.items()
            }
        except AttributeError:
            return {}

    def _get_fan_speeds(self) -> Dict:
        """Get fan speeds if available"""
        try:
            fans = psutil.sensors_fans()
            return {
                name: [{"label": fan.label, "current": fan.current} for fan in entries]
                for name, entries in fans.items()
            }
        except AttributeError:
            return {}

    def _get_battery_info(self) -> Dict:
        """Get battery information if available"""
        try:
            battery = psutil.sensors_battery()
            return (
                {
                    "percent": battery.percent,
                    "secsleft": battery.secsleft,
                    "power_plugged": battery.power_plugged,
                }
                if battery
                else None
            )
        except AttributeError:
            return None

    def _check_binary_signature(self, path: str) -> bool:
        """Check if binary is signed/trusted.

        For Windows: Uses signtool.exe to verify digital signatures
        For Linux: Checks if file comes from package manager or trusted directories
        """
        if not path or not os.path.exists(path):
            return False

        try:
            if platform.system() == "Windows":
                # Windows signature check using signtool
                import subprocess

                try:
                    result = subprocess.run(
                        ["signtool", "verify", "/v", "/pa", path],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    return "Successfully verified" in result.stdout
                except (subprocess.CalledProcessError, FileNotFoundError):
                    # Fallback to checking common Windows directories
                    trusted_paths = [
                        os.environ.get("SystemRoot", r"C:\Windows") + r"\System32",
                        os.environ.get("ProgramFiles", r"C:\Program Files"),
                        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                    ]
                    return any(path.startswith(p) for p in trusted_paths)

            elif platform.system() == "Linux":
                # Linux package manager verification
                import subprocess

                try:
                    # Check if file belongs to a package (RPM/DEB)
                    if os.path.exists("/bin/rpm"):
                        result = subprocess.run(
                            ["rpm", "-qf", "--queryformat", "%{NAME}", path],
                            capture_output=True,
                            text=True,
                        )
                        if result.returncode == 0 and result.stdout.strip():
                            return True

                    if os.path.exists("/usr/bin/dpkg"):
                        result = subprocess.run(
                            ["dpkg", "-S", path], capture_output=True, text=True
                        )
                        if result.returncode == 0 and result.stdout.strip():
                            return True

                    # Check trusted directories
                    trusted_paths = [
                        "/bin",
                        "/sbin",
                        "/usr/bin",
                        "/usr/sbin",
                        "/usr/local/bin",
                        "/opt",
                        "/snap/bin",
                    ]
                    return any(path.startswith(p) for p in trusted_paths)

                except subprocess.SubprocessError:
                    return False

            else:
                # Mac or other OS - use basic path check
                trusted_paths = [
                    "/usr/bin",
                    "/bin",
                    "/sbin",
                    "/usr/sbin",
                    "/usr/local/bin",
                    "/opt/homebrew/bin",
                ]
                return any(path.startswith(p) for p in trusted_paths)

        except Exception as e:
            logger.warning(f"Signature check failed for {path}: {str(e)}")
            return False

    def _is_suspicious_port(self, port: int) -> bool:
        """Detect potentially malicious ports"""
        return port in self.suspicious_ports

    def _check_file_integrity(self, path: str) -> Dict:
        """Check file integrity using hashes"""
        try:
            if not os.path.exists(path) or os.path.isdir(path):
                return {"changed": False, "hash": None}

            with open(path, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()

            changed = False
            if path in self.file_hashes:
                changed = self.file_hashes[path] != file_hash

            self.file_hashes[path] = file_hash
            return {"changed": changed, "hash": file_hash}
        except Exception:
            return {"changed": False, "hash": None}

    def _get_security_context(self, path: str) -> Dict:
        """Get security context for a file"""
        try:
            stat = os.stat(path)
            return {
                "permissions": oct(stat.st_mode)[-3:],
                "owner": stat.st_uid,
                "group": stat.st_gid,
                "last_accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
                "last_modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "last_metadata_change": datetime.fromtimestamp(
                    stat.st_ctime
                ).isoformat(),
            }
        except Exception:
            return {}

    def _check_behavior_anomalies(self) -> Dict:
        """Check for anomalous user behavior"""
        current_hour = datetime.now().hour
        return {
            "is_after_hours": current_hour < 6 or current_hour > 20,
            "is_weekend": datetime.now().weekday() >= 5,
        }

    def _check_system_updates(self) -> bool:
        """Check if system updates are available
        Returns:
            bool: True if updates are available, False otherwise
        """
        try:
            if platform.system() == "Linux":
                # For Debian/Ubuntu systems
                if os.path.exists("/usr/bin/apt"):
                    result = os.popen("apt list --upgradable 2>/dev/null").read()
                    return len(result.strip().split("\n")) > 1

                # For RHEL/CentOS/Fedora systems
                elif os.path.exists("/usr/bin/yum"):
                    result = os.popen("yum check-update -q 2>/dev/null").read()
                    return "updates available" in result.lower()

                # For Arch Linux systems
                elif os.path.exists("/usr/bin/pacman"):
                    result = os.popen("pacman -Qu 2>/dev/null").read()
                    return bool(result.strip())

                # For openSUSE systems
                elif os.path.exists("/usr/bin/zypper"):
                    result = os.popen("zypper list-updates 2>/dev/null").read()
                    return "No updates found" not in result

                return False

            elif platform.system() == "Windows":
                try:
                    import winreg

                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update",
                    ) as key:
                        try:
                            updates_available = winreg.QueryValueEx(
                                key, "UpdatesAvailable"
                            )[0]
                            return updates_available > 0
                        except FileNotFoundError:
                            # Alternative method using PowerShell
                            ps_command = (
                                "$Session = New-Object -ComObject Microsoft.Update.Session; "
                                "$Searcher = $Session.CreateUpdateSearcher(); "
                                "$Result = $Searcher.Search('IsInstalled=0'); "
                                "Write-Output $Result.Updates.Count"
                            )
                            result = os.popen(
                                f'powershell -Command "{ps_command}"'
                            ).read()
                            return int(result.strip()) > 0
                except Exception:
                    return False

            return False
        except Exception as e:
            logger.error(f"Error checking for updates: {e}")
            return False

    def _check_firewall_status(self) -> bool:
        """Check if firewall is active
        Returns:
            bool: True if firewall is active, False otherwise
        """
        try:
            if platform.system() == "Windows":
                # Windows - using netsh command
                import subprocess

                result = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles", "state"],
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                return "ON" in result.stdout

            elif platform.system() == "Linux":
                # Linux - check various firewall daemons
                try:
                    # Check for ufw (Ubuntu)
                    import subprocess

                    result = subprocess.run(
                        ["ufw", "status"], capture_output=True, text=True
                    )
                    if result.returncode == 0 and "active" in result.stdout.lower():
                        return True

                    # Check for firewalld (RHEL/CentOS)
                    result = subprocess.run(
                        ["systemctl", "is-active", "firewalld"],
                        capture_output=True,
                        text=True,
                    )
                    if result.returncode == 0 and "active" in result.stdout.lower():
                        return True

                    # Check for iptables (generic)
                    result = subprocess.run(
                        ["iptables", "-L"], capture_output=True, text=True
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        return True

                    return False

                except FileNotFoundError:
                    # No firewall commands available
                    return False

            else:
                # Unsupported OS
                return False

        except Exception as e:
            logger.error(f"Error checking firewall status: {e}")
            return False

    def _init_baselines(self) -> Dict:
        """Initialize system baselines for anomaly detection"""
        return {
            "cpu": psutil.cpu_percent(interval=1),
            "memory": psutil.virtual_memory().percent,
            "network": psutil.net_io_counters().bytes_sent
            + psutil.net_io_counters().bytes_recv,
            "timestamp": time.time(),
        }
