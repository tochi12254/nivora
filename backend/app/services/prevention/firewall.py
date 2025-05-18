# backend/app/services/prevention/firewall.py
import platform
import subprocess
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Set
import socketio
from ...models.firewall import FirewallRule
from ...database import get_db


class FirewallManager:
    def __init__(self, sio: socketio.AsyncServer):
        self.sio = sio
        self.blocked_ips: Set[str] = set()
        self.os_type = platform.system()

    async def block_ip(self, ip: str, reason: str, duration: int = 3600) -> bool:
        """Block IP across Windows/Linux/macOS with socket.io alerts"""
        try:
            if self.os_type == "Windows":
                cmd = [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "add",
                    "rule",
                    f"name=Block_{ip}",
                    "dir=in",
                    "action=block",
                    f"remoteip={ip}",
                    "protocol=any",
                ]
            elif self.os_type in ["Linux", "Darwin"]:  # Darwin = macOS
                cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            else:
                raise OSError("Unsupported OS")

            subprocess.run(cmd, check=True, capture_output=True)
            self.blocked_ips.add(ip)

            # Log to database
            db = next(get_db())
            db.add(
                FirewallRule(
                    ip=ip,
                    action="BLOCK",
                    reason=reason,
                    expires_at=datetime.utcnow() + timedelta(seconds=duration),
                )
            )
            db.commit()

            # Real-time alert
            await self.sio.emit(
                "firewall_event",
                {
                    "type": "BLOCK",
                    "ip": ip,
                    "reason": reason,
                    "timestamp": datetime.utcnow().isoformat(),
                    "os": self.os_type,
                },
            )

            # Schedule unblock
            asyncio.create_task(self._unblock_after(ip, duration))
            return True

        except subprocess.CalledProcessError as e:
            await self.sio.emit(
                "firewall_error", {"error": str(e), "cmd": " ".join(cmd)}
            )
            return False

    async def _unblock_after(self, ip: str, delay_seconds: int):
        await asyncio.sleep(delay_seconds)
        try:
            if self.os_type == "Windows":
                cmd = [
                    "netsh",
                    "advfirewall",
                    "firewall",
                    "delete",
                    "rule",
                    f"name=Block_{ip}",
                ]
            else:
                cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]

            subprocess.run(cmd, check=True)
            self.blocked_ips.discard(ip)

            await self.sio.emit(
                "firewall_event",
                {
                    "type": "UNBLOCK",
                    "ip": ip,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )
        except Exception as e:
            await self.sio.emit("firewall_error", {"error": str(e)})

    async def get_rules(self) -> Dict:
        """Fetch current firewall rules"""
        try:
            if self.os_type == "Windows":
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
                    capture_output=True,
                    text=True,
                )
            else:
                result = subprocess.run(
                    ["iptables", "-L", "-n", "-v"], capture_output=True, text=True
                )

            return {
                "os": self.os_type,
                "rules": result.stdout,
                "blocked_ips": list(self.blocked_ips),
            }
        except Exception as e:
            return {"error": str(e)}
