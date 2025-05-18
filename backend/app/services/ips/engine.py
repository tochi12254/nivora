# backend/app/services/ips/engine.py
import asyncio
import re
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import socket
import ipaddress
from collections import defaultdict
import logging
from ipaddress import ip_address

from sqlalchemy.ext.asyncio import AsyncSession
from scapy.all import IP, TCP, UDP, ICMP, Raw
from scapy.packet import Packet
from sqlalchemy.orm import Session
from sqlalchemy import select, func, desc,update
import socketio
from ..prevention.app_blocker import ApplicationBlocker
from ...models.ips import IPSRule, IPSEvent
from ...schemas.ips import IPSEventBase
from ...core.security import get_db
# from ..threat_intel import ThreatIntelService
from ..prevention.firewall import FirewallManager
from ..detection.rate_limiter import RateLimiter
from ...database import AsyncSessionLocal
logger = logging.getLogger("ips_engine")

class IPSEngine:
    def __init__(self, sio: socketio.AsyncServer, app_blocker:ApplicationBlocker):
        self.sio = sio
        self.rules: List[IPSRule] = []
        self.rule_cache: Dict[str, IPSRule] = {}
        self.session_counts = defaultdict(int)
        self.session_timers = defaultdict(datetime)
        self.firewall = FirewallManager(sio)
        self.app_blocker = app_blocker  # Use the passed blocker instead of creating new
        self.rate_limiters = {
            "strict": RateLimiter(max_requests=10, time_window=timedelta(minutes=1)),
            "normal": RateLimiter(max_requests=100, time_window=timedelta(minutes=5)),
            "lenient": RateLimiter(max_requests=1000, time_window=timedelta(hours=1))
        }
        self.quarantine_list = set()
        self.db_session_factory = get_db
     
        
        
    async def get_db_session(self) -> AsyncSession:
        """Get a new database session when needed"""
        return await anext(get_db())  # 
    
    async def initialize(self):
        """Initialize the engine with database connection"""
        async with AsyncSessionLocal() as db:
            await self.load_rules(db)
            
    async def _mitigate_threat(self, rule: IPSRule, src_ip: str, 
                             dst_ip: str, dst_port: int, 
                             protocol: str, db: AsyncSession) -> Dict:
        """Enhanced threat mitigation with multiple protection layers"""
        result = {
            "action": rule.action,
            "success": False,
            "message": "",
            "timestamp": datetime.utcnow().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "rule_id": rule.rule_id
        }
        
        try:
            # Get threat context
            threat_context = await self._get_threat_context(src_ip, dst_ip, dst_port, protocol)
            
            if rule.action == "block":
                mitigation_result = await self._handle_block(
                    src_ip, rule, threat_context, db
                )
                 # Use the blocker instance that was passed to IPSEngine
                success = await self.app_blocker.add_to_blocklist(
                    src_ip,
                    reason=f"IPS Block: {rule.name}"
                )
                result.update({
                    "success": success,
                    "message": f"Blocked {src_ip} at application level"
                })
                result.update(mitigation_result)
                
            elif rule.action == "throttle":
                mitigation_result = await self._handle_throttle(
                    src_ip, rule, threat_context, db
                )
                result.update(mitigation_result)
                
            elif rule.action == "quarantine":
                mitigation_result = await self._handle_quarantine(
                    src_ip, rule, threat_context, db
                )
                result.update(mitigation_result)
                
            # Log mitigation result
            await self._log_mitigation(result, db)
            
        except Exception as e:
            error_msg = f"Mitigation failed for rule {rule.rule_id}: {str(e)}"
            result["message"] = error_msg
            logger.error(error_msg, exc_info=True)
            await self.sio.emit("ips_mitigation_failed", result)
            
        return result
    
    async def _handle_block(self, src_ip: str, rule: IPSRule, 
                          context: Dict, db: AsyncSession) -> Dict:
        """Advanced IP blocking with multiple techniques"""
        result = {
            "action": "block",
            "success": False,
            "techniques": []
        }
        
        # 1. System firewall block
        if await self.firewall.block_ip(
            ip=src_ip,
            reason=f"IPS Block: {rule.name}",
            duration=rule.get("block_duration", 86400)  # Default 24 hours
        ):
            result["techniques"].append("firewall_block")
            result["success"] = True
            
        # 2. Application-level block (for web apps)
        if context.get("is_web_traffic"):
            await self._add_to_app_blocklist(src_ip)
            result["techniques"].append("application_block")
            
        # 3. DNS sinkhole for known malware domains
        if context.get("is_malware"):
            await self._sinkhole_domains(src_ip)
            result["techniques"].append("dns_sinkhole")
            
        result["message"] = (
            f"Blocked {src_ip} using {len(result['techniques'])} techniques "
            f"for rule {rule.rule_id}"
        )
        return result

    async def _handle_throttle(self, src_ip: str, rule: IPSRule, 
                            context: Dict, db: AsyncSession) -> Dict:
        """Advanced rate limiting with dynamic thresholds"""
        result = {
            "action": "throttle",
            "success": False,
            "rate_limit_profile": "normal"
        }
        
        # Determine appropriate rate limit profile
        if context.get("is_bruteforce"):
            profile = "strict"
        elif context.get("is_scanner"):
            profile = "moderate"
        else:
            profile = rule.get("rate_limit_profile", "normal")
            
        # Apply rate limiting
        if self.rate_limiters[profile].check_rate_limit(src_ip):
            result.update({
                "success": True,
                "rate_limit_profile": profile,
                "message": (
                    f"Throttled {src_ip} with {profile} profile "
                    f"(max {self.rate_limiters[profile].max_requests} requests/"
                    f"{self.rate_limiters[profile].time_window})"
                )
            })
            
            # Additional throttling measures
            if context.get("is_http_flood"):
                await self._enable_http_throttling(src_ip)
                result["techniques"] = ["request_throttling", "tarpitting"]
                
        return result

    
    async def _handle_quarantine(self, src_ip: str, rule: IPSRule, 
                               context: Dict, db: AsyncSession) -> Dict:
        """Comprehensive quarantine procedure"""
        result = {
            "action": "quarantine",
            "success": False,
            "quarantine_scope": "network"
        }
        
        # 1. Add to quarantine list
        self.quarantine_list.add(src_ip)
        
        # 2. Block at all layers
        await self.firewall.block_ip(src_ip, "Quarantine: "+rule.name, 86400)
        await self._add_to_app_blocklist(src_ip)
        
        # 3. Isolate from internal communications
        if context.get("is_internal"):
            await self._isolate_internal_host(src_ip)
            result["quarantine_scope"] = "full_isolation"
            
        # 4. Notify security team
        await self._notify_security_team(src_ip, rule)
        
        result.update({
            "success": True,
            "message": f"Quarantined {src_ip} with {result['quarantine_scope']} scope",
            "techniques": [
                "firewall_block",
                "application_block",
                "internal_isolation" if context.get("is_internal") else None
            ]
        })
        return result
    
    async def _get_threat_context(self, src_ip: str, dst_ip: str, 
                                dst_port: int, protocol: str) -> Dict:
        """Enrich threat with contextual information"""
        context = {
            "is_internal": self._is_internal_ip(src_ip),
            "is_web_traffic": dst_port in [80, 443, 8080, 8443],
            "is_bruteforce": protocol.lower() in ["ssh", "rdp", "ftp"],
            "is_scanner": await self._is_port_scanner(src_ip),
            "is_http_flood": protocol.lower() == "http" and dst_port in [80, 443],
            "reputation": await self._check_ip_reputation(src_ip)
        }
        context["is_malware"] = context["reputation"].get("threat_score", 0) > 70
        return context
    
    
    async def _log_mitigation(self, result: Dict, db: AsyncSession):
        """Log mitigation action to database"""
        event = IPSEvent(
            rule_id=result["rule_id"],
            action=result["action"],
            severity="high",  # Mitigations are always high severity
            source_ip=result["src_ip"],
            destination_ip=result.get("dst_ip"),
            protocol=result.get("protocol"),
            packet_summary=result["message"],
            mitigated=result["success"],
            threat_intel={
                "mitigation_details": {
                    k: v for k, v in result.items() 
                    if k not in ["src_ip", "dst_ip", "rule_id"]
                }
            }
        )
        db.add(event)
        await db.commit()
    
      # Helper methods
    def _is_internal_ip(self, ip: str) -> bool:
        try:
            return ip_address(ip).is_private
        except ValueError:
            return False

    ##NEEDS MY IMPLEMENTATIONS
    
    async def _check_ip_reputation(self, ip: str) -> Dict:
        """Check IP against threat intelligence feeds"""
        # Implementation depends on your threat intel service
        return {"threat_score": 0}  # Default neutral score

    async def _is_port_scanner(self, ip: str) -> bool:
        """Check if IP exhibits scanning behavior"""
        # Implement scanning detection logic
        return False
    
    
    
    
    async def _add_to_app_blocklist(self, ip: str):
        """Now fully implemented"""
        return await self.app_blocker._add_to_app_blocklist(
            ip, 
            reason="IPS Automated Block"
        )
    
    
    async def _sinkhole_domains(self, ip: str):
        """Sinkhole known malicious domains"""
        # Implementation depends on your DNS infrastructure
        pass
    
    async def _enable_http_throttling(self, ip: str):
        """Enable HTTP request throttling"""
        # Implementation depends on your web server/proxy
        pass
    
    
    async def _isolate_internal_host(self, ip: str):
        """Isolate compromised internal host"""
        # Implementation depends on your network infrastructure
        pass
    
    async def _notify_security_team(self, ip: str, rule: IPSRule):
        """Send notification to security team"""
        alert = {
            "type": "quarantine",
            "ip": ip,
            "rule": rule.name,
            "rule_id": rule.rule_id,
            "timestamp": datetime.utcnow().isoformat(),
            "urgency": "high"
        }
        await self.sio.emit("security_alert", alert)

             
    async def load_rules(self, db: AsyncSession):
        """Load all active rules from database"""
        result = await db.execute(select(IPSRule).where(IPSRule.is_active == True))
        self.rules = result.scalars().all()
        self.rule_cache = {rule.rule_id: rule for rule in self.rules}
        logger.info(f"Loaded {len(self.rules)} active IPS rules")
        
    def _ip_match(self, rule_ip: str, packet_ip: str) -> bool:
        """Check if IP matches rule pattern (supports CIDR and ranges)"""
        if not rule_ip:
            return True
        try:
            if '-' in rule_ip:  # IP range
                start, end = rule_ip.split('-')
                start_ip = ipaddress.ip_address(start.strip())
                end_ip = ipaddress.ip_address(end.strip())
                packet_ip = ipaddress.ip_address(packet_ip)
                return start_ip <= packet_ip <= end_ip
            elif '/' in rule_ip:  # CIDR
                network = ipaddress.ip_network(rule_ip, strict=False)
                return ipaddress.ip_address(packet_ip) in network
            else:  # Exact match
                return rule_ip == packet_ip
        except ValueError:
            logger.error(f"Invalid IP pattern in rule: {rule_ip}")
            return False

    def _port_match(self, rule_port: str, packet_port: int) -> bool:
        """Check if port matches rule pattern (supports ranges and lists)"""
        if not rule_port:
            return True
        try:
            if '-' in rule_port:  # Port range
                start, end = map(int, rule_port.split('-'))
                return start <= packet_port <= end
            elif ',' in rule_port:  # Port list
                ports = list(map(int, rule_port.split(',')))
                return packet_port in ports
            else:  # Exact port
                return int(rule_port) == packet_port
        except ValueError:
            logger.error(f"Invalid port pattern in rule: {rule_port}")
            return False

    def _content_match(self, rule_pattern: str, packet_payload: bytes) -> bool:
        """Check if packet content matches rule pattern"""
        if not rule_pattern:
            return True
        try:
            return re.search(rule_pattern.encode(), packet_payload) is not None
        except re.error:
            logger.error(f"Invalid regex pattern in rule: {rule_pattern}")
            return False

    def _check_threshold(self, rule: IPSRule, src_ip: str) -> bool:
        """Check if event threshold is reached for this rule"""
        if not rule.threshold:
            return True
            
        key = f"{rule.rule_id}:{src_ip}"
        now = datetime.now()
        
        # Reset counter if window expired
        if key in self.session_timers and (now - self.session_timers[key]) > timedelta(seconds=rule.window):
            self.session_counts[key] = 0
            
        self.session_counts[key] += 1
        self.session_timers[key] = now
        
        return self.session_counts[key] >= rule.threshold

    async def process_packet(self, packet: Packet):
        """Main packet processing method"""
        if not IP in packet:
            return
            
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = None
        src_port = None
        dst_port = None
        payload = bytes()
        
        if TCP in packet:
            protocol = "tcp"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            payload = bytes(packet[TCP].payload)
        elif UDP in packet:
            protocol = "udp"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            payload = bytes(packet[UDP].payload)
        elif ICMP in packet:
            protocol = "icmp"
            payload = bytes(packet[ICMP].payload)
        
        # Check against all rules
        for rule in self.rules:
            if not self._ip_match(rule.source_ip, src_ip):
                continue
            if not self._ip_match(rule.destination_ip, dst_ip):
                continue
            if rule.protocol and rule.protocol.lower() != protocol:
                continue
            if not self._port_match(rule.source_port, src_port):
                continue
            if not self._port_match(rule.destination_port, dst_port):
                continue
            if not self._content_match(rule.pattern, payload):
                continue
            if not self._check_threshold(rule, src_ip):
                continue
                
            # Rule matched - take action
            await self._handle_rule_match(rule, packet, src_ip, dst_ip, src_port, dst_port, protocol)

    async def _handle_rule_match(self, rule: IPSRule, packet: Packet, 
                            src_ip: str, dst_ip: str, 
                            src_port: int, dst_port: int, 
                            protocol: str, db: AsyncSession):
        """Handle a matched rule"""
        # Create event record
        event = IPSEvent(
            rule_id=rule.rule_id,
            action=rule.action,
            severity=rule.severity,
            category=rule.category,
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=protocol,
            packet_summary=packet.summary(),
            raw_packet=packet.hexdump(),
            session_data={
                "timestamp": datetime.now().isoformat(),
                "flow_id": f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
            },
            threat_intel=await self.threat_intel.check_ip(src_ip),
            sensor_id="packet_sniffer"
        )
        
        db.add(event)
        await db.commit()
        
        # Update rule stats
        await db.execute(
            update(IPSRule)
            .where(IPSRule.id == rule.id)
            .values(
                last_triggered=datetime.now(),
                true_positives=IPSRule.true_positives + 1
            )
        )
        await db.commit()
        
        # Take mitigation action
        mitigation_result = await self._mitigate_threat(rule, src_ip, dst_ip, dst_port, protocol)
        
        # Send real-time alert
        await self._send_alert(event, mitigation_result)
    
    async def _mitigate_threat(self, rule: IPSRule, src_ip: str, 
                             dst_ip: str, dst_port: int, 
                             protocol: str) -> Dict:
        """Execute mitigation action based on rule"""
        result = {
            "action": rule.action,
            "success": False,
            "message": "",
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            if rule.action == "block":
                # Implement actual blocking logic (iptables, firewall API, etc.)
                result["message"] = f"Blocked {src_ip} -> {dst_ip}:{dst_port}/{protocol}"
                result["success"] = True
                
            elif rule.action == "throttle":
                # Implement rate limiting
                result["message"] = f"Throttled {src_ip} -> {dst_ip}:{dst_port}/{protocol}"
                result["success"] = True
                
            elif rule.action == "quarantine":
                # Implement quarantine logic
                result["message"] = f"Quarantined {src_ip}"
                result["success"] = True
                
        except Exception as e:
            result["message"] = f"Mitigation failed: {str(e)}"
            logger.error(f"Mitigation failed for rule {rule.rule_id}: {str(e)}")
            
        return result

    async def _send_alert(self, event: IPSEvent, mitigation_result: Dict):
        """Send real-time alert via Socket.IO"""
        alert_data = {
            "id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "rule_id": event.rule_id,
            "severity": event.severity,
            "category": event.category,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "protocol": event.protocol,
            "action": event.action,
            "mitigation": mitigation_result,
            "threat_intel": event.threat_intel,
            "packet_summary": event.packet_summary
        }
        
        try:
            await self.sio.emit("ips_alert", alert_data)
            logger.info(f"Sent IPS alert for event {event.id}")
        except Exception as e:
            logger.error(f"Failed to send Socket.IO alert: {str(e)}")
            
            
#blocking implementation