import socket
import struct
from typing import List, Dict, Optional
from dataclasses import dataclass
import logging
import asyncio
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import time
from sqlalchemy import select
from datetime import datetime, timedelta
from models.firewall import FirewallRule, FirewallLog
from app.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


@dataclass
class PacketFilter:
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    interface: Optional[str] = None


class PyFirewall:
    def __init__(self):
        self.rules = []
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.lock = Lock()
        self.running = False
        self._initialized = False

    async def initialize(self):
        """Async initialization"""
        if not self._initialized:
            await self._load_rules()
            self.running = True
            asyncio.create_task(self._enforce_rules())
            self._initialized = True

    async def _load_rules(self):
        """Load rules from database"""
        async with AsyncSessionLocal() as db:
            try:
                result = await db.execute(select(FirewallRule).where(FirewallRule.is_active == True))
                self.rules = result.scalars().all()
                logger.info(f"Loaded {len(self.rules)} firewall rules")
            except Exception as e:
                logger.error(f"Failed to load firewall rules: {str(e)}")
                raise

    async def _enforce_rules(self):
        """Background task to enforce rules"""
        while self.running:
            try:
                await asyncio.sleep(30)
                await self._load_rules()
            except Exception as e:
                logger.error(f"Rule enforcement error: {str(e)}")
                await asyncio.sleep(5)  # Backoff on error

    def add_rule(self, rule: Dict) -> bool:
        """Add a new firewall rule"""
        try:
            db = AsyncSessionLocal()

            # Validate IP addresses
            if rule.get("source_ip"):
                ipaddress.ip_network(rule["source_ip"])
            if rule.get("destination_ip"):
                ipaddress.ip_network(rule["destination_ip"])

            new_rule = FirewallRule(
                action=rule["action"],
                direction=rule["direction"],
                source_ip=rule.get("source_ip"),
                destination_ip=rule.get("destination_ip"),
                source_port=rule.get("source_port"),
                destination_port=rule.get("destination_port"),
                protocol=rule.get("protocol"),
                interface=rule.get("interface"),
                is_active=True,
                created_at=datetime.utcnow(),
            )

            db.add(new_rule)
            db.commit()

            # Reload rules
            self._load_rules()
            return True

        except Exception as e:
            logger.error(f"Failed to add firewall rule: {str(e)}")
            return False
        finally:
            db.close()

    def evaluate_packet(self, packet: Dict) -> bool:
        """Evaluate packet against firewall rules"""
        with self.lock:
            for rule in self.rules:
                if self._match_rule(rule, packet):
                    self._log_action(rule, packet)
                    return rule.action == "allow"

        # Default deny
        self._log_action(None, packet, action="deny")
        return False

    def _match_rule(self, rule: FirewallRule, packet: Dict) -> bool:
        """Check if packet matches rule"""
        # Check direction
        if rule.direction == "in" and packet["direction"] != "in":
            return False
        if rule.direction == "out" and packet["direction"] != "out":
            return False

        # Check protocol
        if rule.protocol and rule.protocol.lower() != packet["protocol"].lower():
            return False

        # Check source IP
        if rule.source_ip:
            try:
                if not ipaddress.ip_address(packet["src_ip"]) in ipaddress.ip_network(
                    rule.source_ip
                ):
                    return False
            except ValueError:
                return False

        # Check destination IP
        if rule.destination_ip:
            try:
                if not ipaddress.ip_address(packet["dst_ip"]) in ipaddress.ip_network(
                    rule.destination_ip
                ):
                    return False
            except ValueError:
                return False

        # Check source port
        if rule.source_port and rule.source_port != packet["src_port"]:
            return False

        # Check destination port
        if rule.destination_port and rule.destination_port != packet["dst_port"]:
            return False

        # Check interface
        if rule.interface and rule.interface != packet["interface"]:
            return False

        return True

    def _log_action(
        self, rule: Optional[FirewallRule], packet: Dict, action: str = None
    ):
        """Log firewall action to database"""
        try:
            db = AsyncSessionLocal()

            log = FirewallLog(
                timestamp=datetime.utcnow(),
                action=action or rule.action,
                rule_id=rule.id if rule else None,
                source_ip=packet["src_ip"],
                destination_ip=packet["dst_ip"],
                source_port=packet["src_port"],
                destination_port=packet["dst_port"],
                protocol=packet["protocol"],
                interface=packet.get("interface"),
                packet_size=packet.get("size", 0),
            )

            db.add(log)
            db.commit()

        except Exception as e:
            logger.error(f"Failed to log firewall action: {str(e)}")
        finally:
            db.close()

    def get_rules(self) -> List[Dict]:
        """Get current firewall rules"""
        return [
            {
                "id": rule.id,
                "action": rule.action,
                "direction": rule.direction,
                "source_ip": rule.source_ip,
                "destination_ip": rule.destination_ip,
                "source_port": rule.source_port,
                "destination_port": rule.destination_port,
                "protocol": rule.protocol,
                "interface": rule.interface,
                "is_active": rule.is_active,
            }
            for rule in self.rules
        ]

    def block_ip(self, ip: str, timeout: int = None) -> bool:
        """Block an IP address temporarily or permanently"""
        try:
            rule = {
                "action": "deny",
                "direction": "in",
                "source_ip": ip,
                "protocol": "any",
                "is_active": True,
            }

            if timeout:
                rule["expires_at"] = datetime.utcnow() + timedelta(seconds=timeout)

            return self.add_rule(rule)
        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {str(e)}")
            return False

    def shutdown(self):
        """Clean shutdown of firewall"""
        self.running = False
        self.executor.shutdown()
