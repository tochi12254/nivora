import asyncio
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, DNS, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from typing import Dict, List, Optional, Tuple
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from ..detection.signature import SignatureEngine
from models.log import NetworkLog
from app.database import AsyncSessionLocal

logger = logging.getLogger(__name__)


class PacketSniffer:
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.signature_engine = SignatureEngine()
        self.active_connections = defaultdict(dict)
        self.arp_table = {}
        self.port_scan_threshold = 5  # Ports per minute
        self.host_scan_threshold = 10  # Hosts per minute
        self.suspicious_activity = defaultdict(int)
        self.last_cleanup = time.time()

    async def start_sniffing(self, interface: str = "Wi-Fi", filter: str = None):
        """Start packet sniffing in background"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(self.executor, self._sync_sniff, interface, filter)

    def _sync_sniff(self, interface: str, filter: str):
        """Synchronous sniffing function to run in thread"""
        sniff(iface=interface, filter=filter, prn=self.process_packet, store=False)

    def process_packet(self, packet):
        """Process each captured packet"""
        try:
            # Cleanup old connections periodically
            if time.time() - self.last_cleanup > 60:
                self._cleanup_old_connections()
                self.last_cleanup = time.time()

            # Basic packet parsing
            if IP in packet:
                self._process_ip_packet(packet)

            if ARP in packet:
                self._process_arp_packet(packet)

            # Signature-based detection
            threat = self.signature_engine.detect(packet)
            if threat:
                self._log_threat(threat, packet)

        except Exception as e:
            logger.error(f"Packet processing error: {str(e)}")

    def _process_ip_packet(self, packet):
        """Process IP layer packets"""
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst

        # Track active connections
        if TCP in packet:
            tcp = packet[TCP]
            self._track_tcp_connection(src_ip, dst_ip, tcp.sport, tcp.dport, tcp.flags)

            # Protocol-specific analysis
            if tcp.dport == 80 or tcp.sport == 80:
                self._analyze_http(packet)
            elif tcp.dport == 22 or tcp.sport == 22:
                self._analyze_ssh(packet)
            elif tcp.dport == 53 or tcp.sport == 53:
                self._analyze_dns(packet)

        elif UDP in packet:
            udp = packet[UDP]
            if udp.dport == 53 or udp.sport == 53:
                self._analyze_dns(packet)

        # Detect port scanning
        self._detect_port_scan(src_ip, dst_ip, packet)

    def _process_arp_packet(self, packet):
        """Process ARP packets for host discovery"""
        arp = packet[ARP]
        if arp.op == 1:  # ARP request
            self.suspicious_activity[arp.psrc] += 1
            if self.suspicious_activity[arp.psrc] > self.host_scan_threshold:
                self._log_threat("ARP Host Scan", packet)
        elif arp.op == 2:  # ARP reply
            self.arp_table[arp.psrc] = arp.hwsrc

    def _track_tcp_connection(self, src_ip, dst_ip, sport, dport, flags):
        """Track TCP connection state"""
        key = (src_ip, dst_ip, sport, dport)

        if "S" in flags and "A" not in flags:  # SYN
            self.active_connections[key]["syn_time"] = time.time()
        elif "S" in flags and "A" in flags:  # SYN-ACK
            if key in self.active_connections:
                self.active_connections[key]["synack_time"] = time.time()
        elif "A" in flags and "S" not in flags:  # ACK
            if key in self.active_connections:
                rtt = time.time() - self.active_connections[key].get(
                    "syn_time", time.time()
                )
                self.active_connections[key]["rtt"] = rtt
                self.active_connections[key]["established"] = True
    def _analyze_http(self, packet):
        """Analyze HTTP traffic"""
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Detect suspicious HTTP patterns
            if ".." in payload or "/etc/passwd" in payload:
                self._log_threat("HTTP Directory Traversal Attempt", packet)
            elif "SELECT" in payload or "UNION" in payload:
                self._log_threat("Possible SQL Injection", packet)
            elif "HTTP/" in payload:  # Basic HTTP response detection
                self._log_threat("HTTP Traffic Detected", packet)
                
    def _analyze_ssh(self, packet):
        """Analyze SSH traffic"""
        tcp = packet[TCP]
        payload = bytes(tcp.payload)

        # Detect SSH version
        if b"SSH-" in payload:
            version = payload.split(b"\r\n")[0].decode(errors="ignore")

            # Detect outdated versions
            if "OpenSSH_7.1" in version:
                self._log_threat("Outdated SSH Version", packet)

    def _analyze_dns(self, packet):
        """Analyze DNS traffic"""
        if DNS in packet:
            dns = packet[DNS]
            if dns.qr == 0:  # DNS query
                query = dns.qd.qname.decode() if dns.qd else ""

                # Detect suspicious DNS queries
                if query.endswith(".xyz") or query.endswith(".top"):
                    self.suspicious_activity[packet[IP].src] += 1
                    if self.suspicious_activity[packet[IP].src] > 5:
                        self._log_threat("Suspicious DNS Query", packet)

    def _detect_port_scan(self, src_ip, dst_ip, packet):
        """Detect port scanning activity"""
        if TCP in packet and packet[TCP].flags == 0x02:  # SYN only
            key = f"{src_ip}-{dst_ip}"
            self.suspicious_activity[key] += 1

            if self.suspicious_activity[key] > self.port_scan_threshold:
                self._log_threat("Port Scanning Detected", packet)

    def _cleanup_old_connections(self):
        """Cleanup old connection tracking"""
        current_time = time.time()
        for key in list(self.active_connections.keys()):
            if (
                current_time
                - self.active_connections[key].get("syn_time", current_time)
                > 300
            ):
                del self.active_connections[key]

    def _log_threat(self, threat_type: str, packet):
        """Log detected threats to database"""
        try:
            db = AsyncSessionLocal()

            log = NetworkLog(
                timestamp=datetime.utcnow(),
                threat_type=threat_type,
                source_ip=packet[IP].src if IP in packet else None,
                destination_ip=packet[IP].dst if IP in packet else None,
                protocol=packet.sprintf("%IP.proto%"),
                length=len(packet),
                raw_data=str(packet),
            )

            db.add(log)
            db.commit()

            # TODO: Send real-time alert via WebSocket
            logger.warning(f"Threat detected: {threat_type} from {log.source_ip}")

        except Exception as e:
            logger.error(f"Error logging threat: {str(e)}")
        finally:
            db.close()

    async def get_network_stats(self):
        """Get current network statistics"""
        return {
            "active_connections": len(self.active_connections),
            "known_hosts": len(self.arp_table),
            "threats_detected": sum(self.suspicious_activity.values()),
        }
