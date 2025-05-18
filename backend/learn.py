import asyncio
import re
from threading import Thread, Event
from queue import Queue, Empty, Full
import math
import ipaddress
from sqlalchemy.inspection import inspect
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

import numpy as np
from scapy.all import (
    sniff,
    Ether,
    IP,
    TCP,
    UDP,
    DNS,
    DNSQR,
    Raw,
    ICMP,
    conf,
    IPv6,
    ARP,
    Dot11,
    PPPoE,
)
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.packet import Packet
import scapy.layers.http as HTTP
from scapy.layers.inet6 import IPv6ExtHdrFragment

from typing import Callable, Dict, Optional, List, Tuple

from datetime import datetime, timedelta
import logging
import math
import socketio
from collections import defaultdict, deque, Counter
import platform
import json
import concurrent
from queue import Queue
from threading import Lock
import time
from ...models.network import NetworkEvent
from ...models.threat import ThreatLog
from ...database import get_db
from ...models.packet import Packets
from ...core.security import get_current_user
from ..detection.rate_limiter import RateLimiter
from ..prevention.firewall import FirewallManager
from ..detection.signature import SignatureEngine
from ..detection.detect_port_scan import PortScanDetector
from ..detection.phishing_blocker import PhishingBlocker


# Configure logging
logger = logging.getLogger("packet_sniffer")
logger.setLevel(logging.INFO)


# Constants for content scanning
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" "abcdefghijklmnopqrstuvwxyz" "0123456789+/="
# Threat scoring weights (adjust based on your priorities)
SCORING_WEIGHTS = {
    # Header Analysis
    "missing_security_headers": 5,
    "spoofed_headers": 20,
    "header_injections": 30,
    # Content Analysis
    "injection_patterns": 25,
    "malicious_payloads": 40,
    "data_exfiltration": 50,
    "path_exfiltration": 35,
    # Behavioral
    "rapid_requests": 15,
    "beaconing": 30,
    "protocol_violations": 20,
    # Critical Threats
    "critical_threat": 100,
}


KNOWN_SERVICES = {
    80: "http",
    443: "https",
    53: "dns",
    22: "ssh",
    25: "smtp",
    3306: "mysql",
    5432: "postgresql",
}


class PacketSniffer:

    def __init__(self, sio: socketio.AsyncServer, main_loop: asyncio.AbstractEventLoop):
        self.sio = sio
        self.main_loop = main_loop
        self._http_listeners: list[Callable[[Dict], bool]] = []
        self._setup_logging()
        self.stop_event = Event()
        self.loop = asyncio.new_event_loop()

        self.byte_distribution = [0] * 256  # For payload byte analysis
        self.service_map = defaultdict(int)
        self.rate_limiter = RateLimiter(
            max_requests=500, time_window=timedelta(seconds=60)
        )

        # Initialize queue and locks first
        self.event_queue = Queue(maxsize=10000)
        self.queue_lock = Lock()

        # Then initialize threads that will use them
        self.processor_thread = Thread(target=self._run_processor, daemon=True)
        self.worker_thread = Thread(target=self._process_queue, daemon=True)

        self.signature_engine = SignatureEngine(sio)
        self.firewall = FirewallManager(sio)
        self.sniffer_thread: Optional[Thread] = None

        # Enhanced statistics with rolling windows
        self.stats = {
            "start_time": datetime.utcnow(),
            "total_packets": 0,
            "protocols": defaultdict(int),
            "top_talkers": defaultdict(int),
            "alerts": deque(maxlen=1000),
            "throughput": {"1min": deque(maxlen=60), "5min": deque(maxlen=300)},
            "geo_data": defaultdict(int),
            "threat_types": defaultdict(int),
        }

        self._last_seen_times = defaultdict(float)  # Track last packet timestamps
        self._dns_counter = defaultdict(lambda: {'total': 0, 'nxdomain': 0})  # DNS stats
        self._endpoint_tracker = defaultdict(lambda: defaultdict(set))  # Track unique endpoints
        self._protocol_counter = defaultdict(Counter)  # Track protocol distribution
        self.recent_packets = defaultdict(lambda: deque(maxlen=100))  # Last 100 packets per IP
        self._data_lock = Lock()  # Thread safety for shared data
        self.current_packet_source = None  # Track source IP of current packet
        self._processing_lock = Lock()  # Separate lock for packet context

        self.port_scan_detector = PortScanDetector()

        # Start threads after all attributes are initialized
        self.processor_thread.start()
        self.worker_thread.start()

        self._setup_event_processor()
        self._setup_periodic_reporting()

    async def stop(self):
        """Graceful shutdown with comprehensive cleanup and monitoring"""
        if not self.stop_event.is_set():
            self.stop_event.set()

            # Send pre-shutdown notification
            await self.sio.emit(
                "system_status",
                {
                    "component": "packet_sniffer",
                    "status": "stopping",
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )

            # Initialize packet_counter if not exists (fixes no-member issue)
            if not hasattr(self, "packet_counter"):
                self.packet_counter = 0
            if not hasattr(self, "start_time"):
                self.start_time = time.time()

            # Thread termination with timeout and monitoring
            threads_to_join = []
            if hasattr(self, "sniffer_thread") and self.sniffer_thread:
                threads_to_join.append(("sniffer_thread", self.sniffer_thread))
            if hasattr(self, "processor_thread") and self.processor_thread:
                threads_to_join.append(("processor_thread", self.processor_thread))

            shutdown_timeout = 10  # seconds
            start_time = time.time()

            for name, thread in threads_to_join:
                try:
                    thread.join(
                        timeout=max(0, shutdown_timeout - (time.time() - start_time))
                    )
                    if thread.is_alive():
                        logger.warning(
                            "%s did not terminate gracefully", name
                        )  # Fixed logging
                except Exception as e:
                    logger.error("Error joining %s: %s", name, str(e))  # Fixed logging

            # Cleanup resources
            try:
                if hasattr(self, "socket"):
                    self.socket.close()
                if hasattr(self, "pcap"):
                    self.pcap.close()
            except Exception as e:
                logger.error("Resource cleanup error: %s", str(e))  # Fixed logging

            # Final status update
            await self.sio.emit(
                "system_status",
                {
                    "component": "packet_sniffer",
                    "status": "stopped",
                    "timestamp": datetime.utcnow().isoformat(),
                    "uptime": time.time() - self.start_time,
                    "packets_processed": self.packet_counter,
                },
            )

            logger.info(
                "Packet sniffer stopped. Processed %d packets. Uptime: %.2f seconds",
                self.packet_counter,
                time.time() - self.start_time,
            )  # Fixed logging

    def _run_processor(self):
        """Run the event processor in its own thread with event loop"""
        asyncio.set_event_loop(self.loop)
        self.loop.run_until_complete(self._async_processor())

    # Modify _async_processor to handle futures
    async def _async_processor(self):
        while True:
            event = self.event_queue.get()
            try:
                if isinstance(event, concurrent.futures.Future):
                    continue  # Already scheduled in main loop
                elif callable(event):
                    event()  # Execute the lambda wrapper
                elif asyncio.iscoroutine(event):
                    await event
            except Exception as e:
                logger.error(f"Event processing failed: {e}")
            finally:
                self.event_queue.task_done()


   

    def get_model_fields(model):
        """Safely get column names from SQLAlchemy model"""
        try:
            return [c.key for c in inspect(model).mapper.column_attrs]
        except Exception as e:
            logger.error(f"Model inspection failed: {str(e)}")
            return []
    
    def _process_queue(self):
        while not self.stop_event.is_set():
            try:
                event = self.event_queue.get(timeout=0.1)
                if asyncio.iscoroutine(event):
                    # Schedule in main ASGI loop
                    asyncio.run_coroutine_threadsafe(event, self.main_loop)
                self.event_queue.task_done()
            except Empty:
                continue

    def _setup_logging(self):
        """Configure packet-level logging"""
        self.packet_logger = logging.getLogger("packet_traffic")
        self.packet_logger.setLevel(logging.INFO)

    def _setup_event_processor(self):
        """Setup the async event processor thread"""
        self.processor_thread = Thread(
            target=self._process_events, daemon=True, name="EventProcessor"
        )
        self.processor_thread.start()

    def _setup_periodic_reporting(self):
        """Setup periodic stats reporting"""

        def reporter():
            while not self.stop_event.is_set():
                time.sleep(60)
                self._queue_event(self._report_system_stats())

        Thread(target=reporter, daemon=True, name="StatsReporter").start()

    async def _report_system_stats(self):
        """Send periodic system statistics"""
        stats = {
            "timestamp": datetime.utcnow().isoformat(),
            "packets_per_minute": sum(self.stats["throughput"]["1min"]),
            "top_talkers": dict(
                sorted(
                    self.stats["top_talkers"].items(), key=lambda x: x[1], reverse=True
                )[:10]
            ),
            "threat_distribution": dict(self.stats["threat_types"]),
            "memory_usage": self._get_memory_usage(),
            "cpu_usage": self._get_cpu_usage(),
        }
        await self.sio.emit("system_stats", stats)

    def _get_memory_usage(self) -> float:
        """Get current memory usage percentage"""
        try:
            import psutil

            return psutil.virtual_memory().percent
        except ImportError:
            return 0.0

    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        try:
            import psutil

            return psutil.cpu_percent()
        except ImportError:
            return 0.0

    def _process_events(self):
        """Process events from the queue in a dedicated thread"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        while not self.stop_event.is_set():
            try:
                event = self.event_queue.get(timeout=1)
                if event:
                    loop.run_until_complete(event)
            except Empty:
                continue
            except Exception as e:
                logger.error(f"Event processing error: {str(e)}")
                self._queue_event(
                    self.sio.emit(
                        "system_error",
                        {
                            "component": "event_processor",
                            "error": str(e),
                            "timestamp": datetime.utcnow().isoformat(),
                        },
                    )
                )

        loop.close()

    def _queue_event(self, item):
        """Handle both coroutines and regular events"""
        with self.queue_lock:
            try:
                self.event_queue.put_nowait(item)
            except Full:
                logger.warning("Event queue full - dropping item")

    def _get_flow_key(self, packet: Packet) -> tuple:
        """Create bidirectional flow key"""
        src_ip = dst_ip = proto = sport = dport = None
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            proto = packet[IPv6].nh

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        return tuple(sorted([src_ip, dst_ip]) + [proto, sport, dport])

    def _get_protocol_name(self, packet: Packet) -> str:
        """Enhanced protocol detection"""
        if packet.haslayer(TCP):
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                return "HTTP"
            elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                return "HTTPS"
            elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                return "SSH"
            return "TCP"
        elif packet.haslayer(UDP):
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                return "DNS"
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(Dot11):
            return "802.11"
        elif packet.haslayer(PPPoE):
            return "PPPoE"
        return "Other"

    def _analyze_tcp_metadata(self, packet: Packet) -> dict:
        """Enhanced TCP metadata analysis"""
        if not packet.haslayer(TCP):
            return {}

        tcp = packet[TCP]
        return {
            "flags": {
                "syn": tcp.flags.S,
                "ack": tcp.flags.A,
                "fin": tcp.flags.F,
                "rst": tcp.flags.R,
                "psh": tcp.flags.P,
                "urg": tcp.flags.U,
                "ece": tcp.flags.E,
                "cwr": tcp.flags.C,
            },
            "window_size": tcp.window,
            "options": str(tcp.options),
            "seq_analysis": {
                "relative_seq": tcp.seq,
                "ack_diff": tcp.ack - tcp.seq,
                "window_ratio": tcp.window / (len(packet) if len(packet) > 0 else 1)
            }
        }

    def _packet_handler(self, packet: Packet):
        """Main packet processing method with enhanced analysis"""
        start_time = time.perf_counter()
        
        try:
            with self._processing_lock:
                
                src_ip = dst_ip = None
                ip_version = None

                # Extract IP information first
                if packet.haslayer(IP):
                    ip_version = 4
                    src_ip = str(packet[IP].src)
                    dst_ip = str(packet[IP].dst)
                elif packet.haslayer(IPv6):
                    ip_version = 6
                    src_ip = str(packet[IPv6].src)
                    dst_ip = str(packet[IPv6].dst)

                # Create packet_info with validated IPs
                packet_info = {
                    'timestamp': datetime.utcnow(),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'ip_version': ip_version,
                    'src_port': None,
                    'dst_port': None,
                    'protocol': self._get_protocol_name(packet),
                    'size': len(packet),
                    'flags': None,
                    'payload': None,
                    'dns_query': None,
                    'http_method': None,
                    'http_path': None
                }

                # Validate essential fields before proceeding
                if not self._validate_packet(packet_info):
                    return

                if packet.haslayer(IP):
                    self.current_packet_source = packet[IP].src
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                elif packet.haslayer(IPv6):
                    self.current_packet_source = packet[IPv6].src
                    src_ip = packet[IPv6].src
                    dst_ip = packet[IPv6].dst
                    
                # Existing flow analysis
                if packet.haslayer(IP):
                    flow_key = (
                        src_ip,
                        dst_ip,
                        packet.sport if hasattr(packet, "sport") else None,
                        packet.dport if hasattr(packet, "dport") else None,
                        packet.proto if hasattr(packet, "proto") else None,
                    )

                # Service mapping
                if packet.haslayer(TCP):
                    self.service_map[packet[TCP].dport] += 1
                    packet_info.update({
                        'src_port': packet[TCP].sport,
                        'dst_port': packet[TCP].dport,
                        'flags': str(packet[TCP].flags)
                    })

                # Byte distribution analysis
                if packet.haslayer(Raw):
                    packet_info["payload"] = packet[Raw].load.hex()
                    for byte in bytes(packet[Raw]):
                        self.byte_distribution[byte] += 1

                # Core processing
                self.stats["total_packets"] += 1
                protocol = self._get_protocol_name(packet)
                self.stats["protocols"][protocol] += 1
                self.stats["throughput"]["1min"].append(1)
                self.stats["throughput"]["5min"].append(1)

                # Layer 3+ analysis
                if packet.haslayer(IP):
                    with self._data_lock:
                        self.recent_packets[src_ip].append({
                            "timestamp": time.time(),
                            "protocol": protocol,
                            "dst_ip": dst_ip,
                            "dst_port": (packet[TCP].dport if packet.haslayer(TCP)
                                        else packet[UDP].dport if packet.haslayer(UDP) 
                                        else None),
                            "length": len(packet),
                        })
                        self._protocol_counter[src_ip][protocol] += 1

                    self._analyze_ip_packet(packet[IP])
                elif packet.haslayer(IPv6):
                    self._analyze_ipv6_packet(packet[IPv6])

                # Application layer analysis
                http_layer = None
                if packet.haslayer(HTTPRequest):
                    http_layer = packet[HTTPRequest]
                elif packet.haslayer(HTTPResponse):
                    http_layer = packet[HTTPResponse]

                if http_layer:
                    packet_info.update({
                        'http_method': self._safe_extract(http_layer, 'Method'),
                        'http_path': self._safe_extract(http_layer, 'Path')
                    })
                    self._analyze_http(packet)
                elif packet.haslayer(DNSQR):
                    dns = packet[DNSQR]
                    packet_info["dns_query"] = self._safe_extract(dns, "qname")
                    logger.info(f"DNS Query: {dns.qname.decode()} (Type:{dns.qtype}) from {src_ip}")
                    self._analyze_dns(packet)
                elif packet.haslayer(TCP) and (packet[TCP].dport == 22 or packet[TCP].sport == 22):
                    self._endpoint_tracker[src_ip]["tcp"].add((dst_ip, packet[TCP].dport))
                    self._analyze_ssh(packet)

                # Threat detection
                self._detect_common_threats(packet)
                if packet.haslayer(HTTPRequest):
                    http = packet[HTTPRequest]
                    logger.info("HTTP %s %s%s from %s",
                            http.Method.decode(),
                            http.Host.decode(),
                            http.Path.decode(),
                            src_ip)

                # UDP handling
                if packet.haslayer(UDP):
                    self._endpoint_tracker[src_ip]["udp"].add((dst_ip, packet[UDP].dport))
                    packet_info.update({
                        'src_port': packet[UDP].sport,
                        'dst_port': packet[UDP].dport
                    })

                # Final validation before logging
                if not packet_info['src_ip'] or not packet_info['dst_ip']:
                    logger.debug(f"Skipping non-IP packet: {packet.summary()}")
                    return

                if not self._final_validation(packet_info):
                    logger.debug(f"Invalid packet format: {packet.summary()}")
                    return

                logger.debug(f"Valid packet ready for DB: {packet_info}")
                self._queue_event(self._log_packet_to_db(packet_info))

        except Exception as e:
            logger.error(f"Packet processing error: {str(e)}")
            self._queue_event(
                self.sio.emit(
                    "system_error",
                    {
                        "component": "packet_handler",
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                )
            )
        finally:
            with self._processing_lock:
                self.current_packet_source = None
                

        
    def _validate_packet(self, packet_info: dict) -> bool:
        """Perform comprehensive packet validation"""
        validation_checks = [
            (packet_info['src_ip'], 'src_ip'),
            (packet_info['dst_ip'], 'dst_ip'),
            (packet_info['protocol'], 'protocol'),
            (packet_info['size'] >= 0, 'size')
        ]

        for value, field in validation_checks:
            if not value:
                logger.debug(f"Invalid {field} in packet: {value}")
                return False

        try:
            if packet_info['src_ip']:
                ipaddress.ip_address(packet_info['src_ip'])
            if packet_info['dst_ip']:
                ipaddress.ip_address(packet_info['dst_ip'])
        except ValueError as e:
            logger.warning(f"Invalid IP format: {str(e)}")
            return False

        return True

    def _final_validation(self, packet_info: dict) -> bool:
        """Validate against known columns"""
        valid_fields = Packets.get_column_names()
        return all(k in valid_fields for k in packet_info.keys())

    def _calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculate entropy of payload data"""
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(x))/data
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _analyze_ip_packet(self, ip_packet):
        """Analyze IPv4 packets"""
        src_ip = ip_packet.src
        dst_ip = ip_packet.dst

        # Update top talkers
        self.stats["top_talkers"][src_ip] += 1
        self.stats["top_talkers"][dst_ip] += 1

        # Rate limiting
        if self.rate_limiter.check_rate_limit(src_ip):
            self._queue_event(
                self.firewall.block_ip(src_ip, "Rate limit exceeded", duration=3600)
            )

    def _analyze_ipv6_packet(self, ipv6_packet):
        """Enhanced IPv6 threat analysis with tunneling detection"""
        src_ip = ipv6_packet.src
        dst_ip = ipv6_packet.dst

        # Update statistics
        self.stats["top_talkers"][src_ip] = self.stats["top_talkers"].get(src_ip, 0) + 1

        # IPv6-specific threat detection
        threats = {
            "tunneling_suspected": False,
            "unusual_extension_headers": False,
            "flood_attempt": False,
        }

        # Detect 6to4 tunneling
        if ipv6_packet.haslayer(IPv6ExtHdrFragment):
            fragment_header = ipv6_packet[IPv6ExtHdrFragment]
            threats["tunneling_suspected"] = fragment_header.offset > 0

        # Check for unusual extension headers
        extension_headers = [h.name for h in ipv6_packet.payload.layers()]
        threats["unusual_extension_headers"] = any(
            h in extension_headers for h in ["HopByHop", "Routing", "Destination"]
        )

        # Emit IPv6-specific events
        ipv6_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "next_header": ipv6_packet.nh,
            "threat_indicators": threats,
            "flow_label": ipv6_packet.fl,
            "payload_length": ipv6_packet.plen,
        }

        self._queue_event(self.sio.emit("ipv6_activity", ipv6_data))

        # Critical threat response
        if threats["tunneling_suspected"]:
            self._queue_event(
                self.sio.emit(
                    "security_alert",
                    {
                        "type": "IPv6 Tunneling Attempt",
                        "severity": "high",
                        "source_ip": src_ip,
                        "description": f"Potential IPv6 tunneling detected from {src_ip}",
                    },
                )
            )

    def _calculate_threat_score(self, http_data: dict) -> dict:
        """Calculate threat score based on detected indicators"""
        score = 0
        indicators = []

        # Header Analysis Scoring
        headers = http_data.get("header_analysis", {})
        if headers.get("security_headers", {}).get("missing_csp"):
            score += SCORING_WEIGHTS["missing_security_headers"]
            indicators.append("missing_csp")

        if headers.get("header_injections"):
            score += SCORING_WEIGHTS["header_injections"]
            indicators.append("header_injections")

        # Content Analysis Scoring
        content = http_data.get("content_analysis", {})
        if content.get("injection_patterns"):
            score += SCORING_WEIGHTS["injection_patterns"]
            indicators.append("injection_patterns")

        if content.get("data_exfiltration"):
            score += SCORING_WEIGHTS["data_exfiltration"]
            indicators.append("data_exfiltration")

        # Behavioral Scoring
        behavior = http_data.get("behavioral_indicators", {})
        if behavior.get("unusual_timing", {}).get("rapid_requests"):
            score += SCORING_WEIGHTS["rapid_requests"]
            indicators.append("rapid_requests")

        if behavior.get("beaconing"):
            score += SCORING_WEIGHTS["beaconing"]
            indicators.append("beaconing")

        # Normalize score to 0-100
        score = min(100, score)

        return {
            "threat_score": score,
            "risk_level": self._get_risk_level(score),
            "contributing_indicators": indicators,
        }

    def _get_risk_level(self, score: int) -> str:
        """Convert score to risk level"""
        if score >= 80:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 30:
            return "medium"
        if score >= 10:
            return "low"
        return "info"

    def _get_nxdomain_ratio(self, queries: list) -> float:
        """Calculate ratio of NXDOMAIN responses with validation"""
        with self._processing_lock:
            if not self.current_packet_source:
                logger.debug("Missing source context for NXDOMAIN ratio")
                return 0.0

            counter = self._dns_counter.get(self.current_packet_source, 
                                          {'total': 0, 'nxdomain': 0})
            total = counter['total']
        return round(counter['nxdomain'] / total, 4) if total > 0 else 0.0

    def _calculate_inter_arrival(self, packet: Packet) -> float:
        """Calculate time between consecutive packets from same source"""

        if not packet.haslayer(IP):
            return 0.0

        src_ip = packet[IP].src
        current_time = time.time()

        with self._data_lock:
            last_time = self._last_seen_times.get(src_ip, current_time)
            interval = current_time - last_time
            self._last_seen_times[src_ip] = current_time

        return round(interval, 6)

    def _get_protocol_ratio(self, src_ip: str) -> dict:
        """Get protocol distribution ratios for a source IP"""
        with self._data_lock:
            counter = self._protocol_counter.get(src_ip, Counter())
            total = sum(counter.values())

            if total == 0:
                return {}

            return {
                proto: count / total
                for proto, count in counter.most_common()
            }

    def _get_unique_endpoints(self, src_ip: str) -> dict:
        """Get unique destination endpoints for a source IP"""
        with self._data_lock:
            endpoints = self._endpoint_tracker.get(src_ip, {})

            # Debug: print the actual data
            logger.debug(f"endpoints for {src_ip}: {endpoints}")

            # If there is data, check port types
            if endpoints:
                for proto, ports in endpoints.items():
                    logger.debug(f"Protocol: {proto}, Ports: {ports}, Port types: {[type(p) for p in ports]}")

            return {
                'total': sum(len(ports) for ports in endpoints.values()),
                'per_protocol': {
                    proto: len(ports) 
                    for proto, ports in endpoints.items()
                }
            }

    def _analyze_http(self, packet: Packet):
        """Comprehensive HTTP analysis with advanced threat detection"""
        http_layer = None
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
        elif packet.haslayer(HTTPResponse):
            http_layer = packet[HTTPResponse]

        if not http_layer:
            return

        #  Payload extraction with chunked encoding support
        payload = self._extract_http_payload(packet)

        # Extract all HTTP components with safety checks
        http_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": packet[IP].src if packet.haslayer(IP) else None,
            "destination_ip": packet[IP].dst if packet.haslayer(IP) else None,
            "host": self._safe_extract(http_layer, "Host"),
            "path": self._safe_extract(http_layer, "Path"),
            "method": self._safe_extract(http_layer, "Method"),
            "user_agent": self._safe_extract(http_layer, "User_Agent"),
            "version": self._safe_extract(http_layer, "Http_Version"),
            "referer": self._safe_extract(http_layer, "Referer"),
            "content_type": self._safe_extract(http_layer, "Content_Type"),
            "threat_indicators": {},
            "header_analysis": {},
            "content_analysis": {},
            "behavioral_indicators": {},
        }

        http_data.update({
            "network_metrics": {
                "packet_size": len(packet),
                "inter_arrival_time": self._calculate_inter_arrival(packet),
                "protocol_ratio": self._get_protocol_ratio(packet[IP].src),
                "unique_endpoints": self._get_unique_endpoints(packet[IP].src),
                "tcp_metrics": self._analyze_tcp_metadata(packet),
                "payload_characteristics": {
                    "entropy": self._calculate_entropy(payload),
                    "hex_patterns": self._find_hex_patterns(payload),
                    "printable_ratio": sum(32 <= c < 127 for c in payload)/len(payload) if payload else 0
                }
            },
            "session_context": {
                "request_count": self._get_session_count(packet[IP].src),
                "unique_endpoints": self._get_unique_endpoints(packet[IP].src)
            }
        })

        # Enhanced header analysis
        http_data["header_analysis"] = {
            "spoofed_headers": self._check_header_spoofing(http_layer),
            "injection_vectors": self._detect_header_injections(http_layer),
            "security_headers": self._check_security_headers(http_layer),
            "header_manipulation": self._detect_header_tampering(http_layer),
        }

        # Advanced content analysis
        http_data["content_analysis"] = {
            "injection_patterns": self._detect_content_injections(payload),
            "malicious_payloads": self._scan_malicious_patterns(payload),
            "data_exfiltration": self._detect_payload_exfiltration(
                payload
            ),  # Just payload
            "path_exfiltration": self._detect_path_exfiltration(
                http_data["path"]
            ),  # Separate check
            "encoding_analysis": self._analyze_encodings(payload),
        }

        # Behavioral analysis
        http_data["behavioral_indicators"] = {
            "unusual_timing": self._check_request_timing(packet),
            "beaconing": self._detect_beaconing(http_data),
            "protocol_violations": self._check_protocol_anomalies(http_layer),
        }

        scoring_data = self._calculate_threat_score(http_data)
        http_data["threat_analysis"] = scoring_data

        # Critical threat detection
        critical_threats = self._detect_critical_threats(http_data, payload)
        if critical_threats:
            self._queue_event(
                self.sio.emit(
                    "critical_alert",
                    {
                        **critical_threats,
                        "raw_packet_summary": packet.summary(),
                        "mitigation_status": "pending",
                    },
                )
            )

        # Signature-based detection
        if payload:
            sig_results = self.signature_engine.scan_packet(payload)
            if sig_results:
                self._queue_event(
                    self.sio.emit(
                        "signature_match", {**sig_results, "context": http_data}
                    )
                )
        # emit to the frontend

        self._queue_event(self.sio.emit("http_activity", http_data))

    def _calculate_entropy(self, payload: bytes) -> float:
        """Calculate payload entropy for encrypted traffic detection"""
        if not payload:
            return 0.0
        counts = Counter(payload)
        probs = [c/len(payload) for c in counts.values()]
        return -sum(p * math.log2(p) for p in probs)

    def _find_hex_patterns(self, payload: bytes) -> dict:
        """Identify suspicious hex patterns"""
        return {
            "magic_bytes": payload[:4].hex() if len(payload) >=4 else None,
            "repeated_hex": bool(re.search(rb"(\x00{4,}|\xCC{4,})", payload)),
            "non_printable_ratio": sum(c < 32 or c >= 127 for c in payload)/len(payload) if payload else 0
        }

    def _get_session_count(self, src_ip: str) -> dict:
        """Get session statistics for source IP"""
        return {
            "total_requests": self.stats["top_talkers"].get(src_ip, 0),
            "unique_ports": len(self.port_scan_detector.port_counter[src_ip]),
            "protocol_distribution": dict(
                Counter([p["protocol"] for p in self.recent_packets.get(src_ip, [])])
            ),
        }

    def _check_security_headers(self, http_layer) -> dict:
        """Analyze HTTP headers for security best practices"""
        security_checks = {
            "missing_csp": False,
            "insecure_csp": False,
            "missing_hsts": False,
            "hsts_short_max_age": False,
            "missing_xcto": False,
            "missing_xfo": False,
            "missing_xxp": False,
            "missing_rp": False,
            "insecure_cookies": False,
        }

        headers = {}
        # Convert all headers to lowercase for case-insensitive checks
        if hasattr(http_layer, "fields"):
            headers = {k.lower(): v for k, v in http_layer.fields.items()}
        elif hasattr(http_layer, "headers"):
            headers = {k.lower(): v for k, v in http_layer.headers.items()}

        # Content Security Policy Check
        if "content-security-policy" not in headers:
            security_checks["missing_csp"] = True
        else:
            csp = headers["content-security-policy"].lower()
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                security_checks["insecure_csp"] = True

        # Strict Transport Security Check
        if "strict-transport-security" not in headers:
            security_checks["missing_hsts"] = True
        else:
            hsts = headers["strict-transport-security"]
            if "max-age=" in hsts:
                try:
                    max_age = int(hsts.split("max-age=")[1].split(";")[0])
                    if max_age < 31536000:  # 1 year minimum recommended
                        security_checks["hsts_short_max_age"] = True
                except (ValueError, IndexError):
                    pass

        # X-Content-Type-Options Check
        if "x-content-type-options" not in headers:
            security_checks["missing_xcto"] = True
        elif headers["x-content-type-options"].lower() != "nosniff":
            security_checks["missing_xcto"] = True

        # X-Frame-Options Check
        if "x-frame-options" not in headers:
            security_checks["missing_xfo"] = True
        else:
            xfo = headers["x-frame-options"].lower()
            if xfo not in ["deny", "sameorigin"]:
                security_checks["missing_xfo"] = True

        # X-XSS-Protection Check (legacy but still useful)
        if "x-xss-protection" not in headers:
            security_checks["missing_xxp"] = True
        else:
            xxp = headers["x-xss-protection"].lower()
            if "0" in xxp:  # Disabled protection
                security_checks["missing_xxp"] = True

        # Referrer-Policy Check
        if "referrer-policy" not in headers:
            security_checks["missing_rp"] = True
        else:
            rp = headers["referrer-policy"].lower()
            if rp in ["unsafe-url", ""]:
                security_checks["missing_rp"] = True

        # Cookie Security Checks
        if "set-cookie" in headers:
            cookies = (
                headers["set-cookie"]
                if isinstance(headers["set-cookie"], list)
                else [headers["set-cookie"]]
            )
            for cookie in cookies:
                cookie_lower = cookie.lower()
                if "secure" not in cookie_lower:
                    security_checks["insecure_cookies"] = True
                if "httponly" not in cookie_lower:
                    security_checks["insecure_cookies"] = True
                if "samesite=" not in cookie_lower:
                    security_checks["insecure_cookies"] = True
                elif "samesite=none" in cookie_lower and "secure" not in cookie_lower:
                    security_checks["insecure_cookies"] = True

        return security_checks

    def _detect_header_tampering(self, http_layer) -> dict:
        """Detect suspicious header modifications and inconsistencies"""
        tampering_indicators = {
            "header_injection": False,
            "duplicate_headers": False,
            "obfuscated_headers": False,
            "invalid_format": False,
            "unusual_casing": False,
            "malformed_values": False,
        }

        headers = {}
        if hasattr(http_layer, "fields"):
            headers = http_layer.fields
        elif hasattr(http_layer, "headers"):
            headers = http_layer.headers

        # Check for CR/LF injection attempts
        for header, value in headers.items():
            if isinstance(value, str):
                # Header injection patterns
                if any(c in value for c in ["\r", "\n", "\0"]):
                    tampering_indicators["header_injection"] = True

                # Obfuscation detection
                if any(ord(c) > 127 for c in value):  # Non-ASCII
                    tampering_indicators["obfuscated_headers"] = True

                # Unusual header casing
                if header != header.title():  # Standard is Title-Case
                    tampering_indicators["unusual_casing"] = True

                # Malformed values
                if ";" in value and "=" not in value:
                    tampering_indicators["malformed_values"] = True

        # Check for duplicate headers
        if isinstance(headers, dict) and len(headers) != len(
            {k.lower() for k in headers.keys()}
        ):
            tampering_indicators["duplicate_headers"] = True

        # Special checks for specific headers
        for header in ["content-length", "host", "user-agent"]:
            if header in headers:
                value = headers[header]
                if header == "content-length":
                    if not value.isdigit() or int(value) < 0:
                        tampering_indicators["invalid_format"] = True
                elif header == "host":
                    if ":" in value and not value.endswith("]"):  # IPv6 check
                        port_part = value.split(":")[-1]
                        if not port_part.isdigit():
                            tampering_indicators["invalid_format"] = True

        return tampering_indicators

    def _safe_extract(self, layer: Packet, attribute: str) -> Optional[str]:
        """
        Safely extract attributes from HTTP layers with comprehensive error handling

        Args:
            layer: Scapy packet layer (HTTPRequest/HTTPResponse)
            attribute: Attribute name to extract

        Returns:
            Decoded string or None if attribute doesn't exist or decoding fails
        """
        try:
            if not hasattr(layer, attribute):
                return None

            value = getattr(layer, attribute)
            if value is None:
                return None

            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")
            return str(value)

        except Exception as e:
            logger.debug(f"Failed to extract {attribute}: {str(e)}")
            return None

    def _detect_content_injections(self, payload: bytes) -> dict:
        """Detect various code injection patterns"""
        if not payload:
            return {}

        content = payload.decode(errors="ignore").lower()

        return {
            "sql_injection": any(
                re.search(pattern, content)
                for pattern in [
                    r"union\s+select",
                    r"\d+=\d+",
                    r"waitfor\s+delay",
                    r"sleep\(\d+\)",
                ]
            ),
            "xss": any(
                pattern in content
                for pattern in ["<script>", "javascript:", "onerror=", "alert("]
            ),
            "command_injection": any(
                re.search(pattern, content)
                for pattern in [
                    r"(?:;|\||&&)\s*(?:sh|bash|cmd|powershell)\b",
                    r"\$(?:\{|\().*?(?:\}|\))",
                    r"`.*?`",
                ]
            ),
            "template_injection": any(
                pattern in content for pattern in ["{{", "}}", "<%", "%>"]
            ),
        }

    def _scan_malicious_patterns(self, payload: bytes) -> dict:
        """Detect known malicious payload patterns"""
        if not payload:
            return {}

        content = payload.decode(errors="ignore")

        # Indicators for common attack patterns
        return {
            "web_shells": any(
                re.search(pattern, content, re.I)
                for pattern in [
                    r"eval\(base64_decode\(",
                    r"system\(\$_GET\[",
                    r"passthru\(\$_POST\[",
                    r"shell_exec\(",
                ]
            ),
            "c2_indicators": any(
                re.search(pattern, content, re.I)
                for pattern in [
                    r"(?:https?://)[^\s/]+\.(?:php|asp|jsp)\?[a-z0-9]+=",
                    r"(?:[a-z0-9]{16,}\.(?:php|asp|jsp))",
                    r"cmd\.exe\s+/c",
                ]
            ),
            "obfuscation": any(
                re.search(pattern, content)
                for pattern in [
                    r"\w{30,}",  # Long random strings
                    r"[0-9a-f]{20,}",  # Long hex strings
                    r"(?:[A-Za-z0-9+/]{4}){10,}",  # Base64 patterns
                    r"\$(?:\w+\$)+\w+",  # PHP variable variables
                ]
            ),
        }

    def _analyze_encodings(self, payload: bytes) -> dict:
        """Detect suspicious encoding patterns"""
        if not payload:
            return {}

        content = payload.decode(errors="ignore")

        return {
            "double_encoded": any(
                pattern in content
                for pattern in [
                    "%2520",  # Double URL encoding
                    "&#x",  # Hex HTML entities
                    "\\u00",  # Unicode escapes
                ]
            ),
            "non_standard": any(
                re.search(pattern, content)
                for pattern in [
                    r"%[0-9a-f]{2}%[0-9a-f]{2}",  # Repeated URL encoding
                    r"&#\d+;",  # HTML entities
                    r"\\x[0-9a-f]{2}",  # Hex escapes
                ]
            ),
            "compression": any(
                content.startswith(magic)
                for magic in [
                    b"\x1f\x8b",  # Gzip
                    b"\x78\x01",  # Zlib
                    b"\x42\x5a\x68",  # Bzip2
                ]
                if payload.startswith(magic)
            ),
        }

    def _check_request_timing(self, packet: Packet) -> dict:
        """Detect timing-based anomalies"""
        current_time = time.time()

        if not hasattr(self, "last_request_time"):
            self.last_request_time = {}

        src_ip = packet[IP].src if packet.haslayer(IP) else None
        if not src_ip:
            return {}

        # Calculate time delta
        time_delta = current_time - self.last_request_time.get(src_ip, current_time)
        self.last_request_time[src_ip] = current_time

        return {
            "rapid_requests": time_delta < 0.1,  # >10 requests/sec
            "slowloris_indicator": time_delta > 5
            and packet.haslayer(TCP)
            and packet[TCP].flags == "S",  # Slow connection setup
            "beaconing_pattern": 0.9 < time_delta % 60 < 1.1,  # ~60s intervals
        }

    def _scan_content(self, payload: bytes) -> dict:
        """Analyze HTTP payload for suspicious content patterns"""
        content_str = payload.decode(errors="ignore").lower()

        return {
            "base64_encoded": any(
                len(chunk) > 50 and all(c in BASE64_CHARS for c in chunk)
                for chunk in content_str.split()
            ),
            "executable_patterns": any(
                pattern in content_str
                for pattern in ["<script>", "eval(", "fromcharcode", "cmd.exe"]
            ),
            "long_hex_strings": bool(re.search(r"(?:[0-9a-f]{20,})", content_str)),
        }

    def _check_protocol_anomalies(self, http_layer) -> dict:
        """Detect HTTP protocol violations"""
        anomalies = {}

        if hasattr(http_layer, "Method"):
            method = http_layer.Method.decode(errors="ignore")
            anomalies["invalid_method"] = method not in [
                "GET",
                "POST",
                "HEAD",
                "PUT",
                "DELETE",
                "OPTIONS",
                "PATCH",
            ]

        if hasattr(http_layer, "Http_Version"):
            version = http_layer.Http_Version.decode(errors="ignore")
            anomalies["version_spoofing"] = not version.startswith("HTTP/1.")

        if hasattr(http_layer, "Headers"):
            headers = str(http_layer.Headers)
            anomalies["header_overflow"] = len(headers) > 8192  # 8KB header limit
            anomalies["crlf_injection"] = any(
                marker in headers for marker in ["\r\n\r\n", "\n\n"]
            )

        return anomalies

    def _decode_chunked(self, payload: bytes) -> bytes:
        """Decode HTTP chunked transfer encoding"""
        try:
            decoded = bytearray()
            while payload:
                # Find chunk size
                chunk_end = payload.find(b"\r\n")
                if chunk_end == -1:
                    break

                chunk_size = int(payload[:chunk_end], 16)
                if chunk_size == 0:
                    break  # End of chunks

                # Extract chunk data
                chunk_start = chunk_end + 2
                chunk_data = payload[chunk_start : chunk_start + chunk_size]
                decoded.extend(chunk_data)

                # Move to next chunk
                payload = payload[chunk_start + chunk_size + 2 :]

            return bytes(decoded)
        except Exception as e:
            logger.warning(f"Chunked decode failed: {str(e)}")
            return payload  # Return original if decoding fails

    def _decompress_gzip(self, payload: bytes) -> bytes:
        """Decompress GZIP-encoded HTTP payload"""
        try:
            import zlib

            # Skip header if present
            if payload.startswith(b"\x1f\x8b"):
                return zlib.decompress(payload, 16 + zlib.MAX_WBITS)
            return payload
        except Exception as e:
            logger.warning(f"GZIP decompress failed: {str(e)}")
            return payload

    # New separate methods:
    def _detect_payload_exfiltration(self, payload: bytes) -> bool:
        """Check payload for sensitive data patterns"""
        if not payload:
            return False
        return any(
            p in payload.decode(errors="ignore").lower()
            for p in ["ccnum=", "password=", "secret="]
        )

    def _detect_path_exfiltration(self, path: str) -> bool:
        """Check URL path for exfiltration signs"""
        if not path:
            return False
        return len(path) > 200 and any(c in path for c in ["=", "/", "+"])

    def _extract_http_payload(self, packet: Packet) -> bytes:
        """Handle chunked encoding and compressed payloads"""
        payload = bytes(packet[Raw].payload) if packet.haslayer(Raw) else b""

        if packet.haslayer(HTTP) and hasattr(packet[HTTP], "Transfer_Encoding"):
            if "chunked" in packet[HTTP].Transfer_Encoding:
                payload = self._decode_chunked(payload)

        if packet.haslayer(HTTP) and hasattr(packet[HTTP], "Content_Encoding"):
            if "gzip" in packet[HTTP].Content_Encoding:
                payload = self._decompress_gzip(payload)

        return payload

    def _detect_critical_threats(
        self, http_data: dict, payload: bytes
    ) -> Optional[dict]:
        """Check for immediately actionable threats"""
        threats = {}

        # Web shell detection
        if http_data["path"] and any(
            p in http_data["path"].lower() for p in ["/cmd.php", "/shell", "/backdoor"]
        ):
            threats["web_shell"] = True

        # RCE patterns
        rce_patterns = [
            r"system\(",
            r"exec\(",
            r"passthru\(",
            r"popen\(",
            r"proc_open\(",
            r"`.*`",
        ]
        if any(re.search(p, payload.decode(errors="ignore")) for p in rce_patterns):
            threats["rce_attempt"] = True

        # SQL injection patterns
        sql_patterns = [
            r"union\s+select",
            r"1=1--",
            r"waitfor\s+delay",
            r"sleep\(\d+\)",
            r"benchmark\(",
        ]
        if any(re.search(p, payload.decode(errors="ignore")) for p in sql_patterns):
            threats["sql_injection"] = True

        if threats:
            return {
                "type": "Critical HTTP Threat",
                "severity": "critical",
                "source_ip": http_data["source_ip"],
                "indicators": threats,
                "timestamp": http_data["timestamp"],
            }
        return None

    def _detect_beaconing(self, http_data: dict) -> bool:
        """Detect potential C2 beaconing behavior"""
        if not http_data["host"]:
            return False

        # Check against known beaconing patterns
        beacon_domains = ["azure-api.net", "aws.amazon.com", "googleapis.com"]

        return (
            http_data["host"] in beacon_domains
            and http_data["method"] == "GET"
            and len(http_data.get("path", "")) < 30  # Short paths common in beacons
        )

    def _check_header_spoofing(self, http_layer) -> list:
        """Detect header spoofing attempts"""
        suspicious = []
        if hasattr(http_layer, "Headers"):
            headers = str(http_layer.Headers)

            # Common spoofing indicators
            if "X-Forwarded-For: 127.0.0.1" in headers:
                suspicious.append("localhost_spoofing")
            if "Via:" in headers and "Proxy-Authorization" not in headers:
                suspicious.append("proxy_spoofing")

        return suspicious

    def _detect_header_injections(self, http_layer) -> list:
        """Detect HTTP header injection attempts"""
        injections = []
        if hasattr(http_layer, "Headers"):
            headers = str(http_layer.Headers)

            # CRLF injection patterns
            if any(pattern in headers for pattern in ["\r\n", "%0d%0a", "\\r\\n"]):
                injections.append("crlf_injection")

            # HTTP response splitting
            if "Set-Cookie:" in headers and ("\n" in headers or "\r" in headers):
                injections.append("response_splitting")

        return injections

    def _detect_c2_patterns(self, http_data: dict) -> bool:
        """Check for Command & Control patterns"""
        c2_indicators = [
            r"(?:[a-z0-9]{16,}\.php)",  # Long random PHP files
            r"(?:cmd|whoami|ipconfig)\=",  # Common commands
            r"(?:sleep\(\d+\))",  # Time delay patterns
        ]
        return any(
            re.search(pattern, http_data["path"] or "", re.I)
            for pattern in c2_indicators
        )

    def _analyze_dns(self, packet: Packet):
        """Enhanced DNS analysis with TTL monitoring"""
        dns = packet[DNS]
        queries = []
        responses = []

        if dns.qr == 0:  # Query
            if dns.qd:
                query = {
                    "name": dns.qd.qname.decode(errors="replace"),
                    "type": dns.qd.qtype,
                }
                queries.append(query)

        else:  # Response
            for i in range(dns.ancount):
                if dns.an:
                    answer = {
                        "name": dns.an[i].rrname.decode(errors="replace"),
                        "type": dns.an[i].type,
                        "ttl": dns.an[i].ttl,
                        "data": (
                            str(dns.an[i].rdata)
                            if hasattr(dns.an[i], "rdata")
                            else None
                        ),
                    }
                    responses.append(answer)

        if dns.qr == 1:  # Response
            with self._data_lock:
                src_ip = packet[IP].src
                self._dns_counter[src_ip]['total'] += 1

                if dns.rcode == 3:  # NXDOMAIN
                    self._dns_counter[src_ip]['nxdomain'] += 1

        dns_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": packet[IP].src if packet.haslayer(IP) else None,
            "queries": queries,
            "responses": responses,
            "is_suspicious": any(q["type"] in [12, 16] for q in queries),  # PTR or TXT
        }

        dns_data["tunnel_analysis"] = {
            "likely_tunnel": self._detect_dns_tunneling(queries, responses),
            "dga_score": self._calculate_dga_score(queries),
        }

        # TTL anomaly detection
        if responses:
            avg_ttl = sum(r["ttl"] for r in responses) / len(responses)
            dns_data["ttl_anomaly"] = (
                avg_ttl < 30
            )  # Low TTL often indicates malicious domains

        dns_data.update(
            {
                "correlation_features": {
                    "query_chain_depth": len(
                        [rr for rr in responses if rr["type"] == 5]
                    ),
                    "nxdomain_ratio": self._get_nxdomain_ratio(queries),
                    "ttl_variation": (
                        np.std([r["ttl"] for r in responses]) if responses else 0
                    ),
                    "subdomain_entropy": self._calculate_subdomain_entropy(queries),
                }
            }
        )

        dns_data.update(
            {
                "nxdomain_ratio": self._get_nxdomain_ratio(queries),
                "unique_domains": len({q["name"] for q in queries}),
            }
        )

        self._queue_event(self.sio.emit("dns_activity", dns_data))

    def _calculate_subdomain_entropy(self, queries: list) -> float:
        """Calculate entropy of subdomain labels"""
        labels = [q["name"].split('.')[-2] for q in queries if '.' in q["name"]]
        counter = Counter(labels)
        probs = [c/len(labels) for c in counter.values()]
        return -sum(p * math.log2(p) for p in probs) if labels else 0

    def _calculate_dga_score(self, queries: list) -> float:
        """
        Calculate likelihood of DGA (Domain Generation Algorithm) usage based on:
        - N-gram frequency analysis
        - Domain length and entropy
        - Subdomain patterns
        - TLD distribution

        Returns: Score between 0 (benign) and 1 (highly likely DGA)
        """
        if not queries:
            return 0.0

        total_score = 0.0
        analyzed_domains = 0

        # English language n-gram frequencies (pre-computed)
        COMMON_BIGRAMS = {"th", "he", "in", "er", "an", "re", "on", "at", "en", "nd"}
        COMMON_TRIGRAMS = {
            "the",
            "and",
            "ing",
            "her",
            "hat",
            "his",
            "tha",
            "ere",
            "for",
            "ent",
        }

        for query in queries:
            if not query.get("name"):
                continue

            domain = query["name"].lower().rstrip(".")
            if not domain or len(domain) < 4:
                continue

            domain_parts = domain.split(".")
            main_domain = domain_parts[-2] if len(domain_parts) > 1 else domain_parts[0]
            subdomain = ".".join(domain_parts[:-2]) if len(domain_parts) > 2 else ""

            # Initialize metrics
            metrics = {
                "length_score": 0,
                "entropy_score": 0,
                "ngram_score": 0,
                "subdomain_score": 0,
                "tld_score": 0,
            }

            # 1. Length analysis (long domains are suspicious)
            metrics["length_score"] = min(1, len(main_domain) / 30)  # Normalize 0-1

            # 2. Entropy calculation (high entropy = random-looking)
            char_counts = Counter(main_domain)
            entropy = -sum(
                (count / len(main_domain)) * math.log2(count / len(main_domain))
                for count in char_counts.values()
            )
            metrics["entropy_score"] = min(
                1, entropy / 4
            )  # Max entropy for a-z is ~4.7

            # 3. N-gram analysis (matches against known language patterns)
            bigrams = {main_domain[i : i + 2] for i in range(len(main_domain) - 1)}
            trigrams = {main_domain[i : i + 3] for i in range(len(main_domain) - 2)}

            metrics["ngram_score"] = 1 - (
                (len(bigrams & COMMON_BIGRAMS) + len(trigrams & COMMON_TRIGRAMS))
                / (len(bigrams) + len(trigrams) + 1e-6)
            )

            # 4. Subdomain analysis (random subdomains are suspicious)
            if subdomain:
                sub_entropy = -sum(
                    (count / len(subdomain)) * math.log2(count / len(subdomain))
                    for count in Counter(subdomain).values()
                )
                metrics["subdomain_score"] = min(1, sub_entropy / 4) * 0.7  # Weighted

            # 5. TLD analysis (uncommon TLDs increase suspicion)
            uncommon_tlds = {"xyz", "top", "gq", "cf", "pw"}
            tld = domain_parts[-1]
            metrics["tld_score"] = 0.8 if tld in uncommon_tlds else 0.1

            # Weighted combined score
            weights = {
                "length_score": 0.15,
                "entropy_score": 0.30,
                "ngram_score": 0.25,
                "subdomain_score": 0.15,
                "tld_score": 0.15,
            }

            domain_score = sum(
                metrics[metric] * weight for metric, weight in weights.items()
            )

            total_score += min(1, domain_score * 1.2)  # Cap at 1.0
            analyzed_domains += 1

        if analyzed_domains == 0:
            return 0.0

        # Average score across all queries with nonlinear scaling
        avg_score = total_score / analyzed_domains
        return round(avg_score**1.5, 2)  # Make scores >0.7 rarer

    def _detect_dns_tunneling(self, queries: list, responses: list) -> bool:
        """Detect DNS tunneling attempts"""
        suspicious = False
        for q in queries:
            # Check for long subdomains or encoded data
            if len(q["name"]) > 60 or any(c in q["name"] for c in ["_", "=", "/"]):
                suspicious = True
        return suspicious

    def _analyze_ssh(self, packet: Packet):
        """Enhanced SSH analysis with version detection"""
        ssh_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": packet[IP].src if packet.haslayer(IP) else None,
            "destination_ip": packet[IP].dst if packet.haslayer(IP) else None,
            "is_encrypted": False,
        }

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            try:
                banner = payload.decode("utf-8", errors="replace")
                ssh_data["banner"] = banner[:100]  # Truncate long banners

                # Detect brute force patterns
                if "Failed password" in banner or "Invalid user" in banner:
                    ssh_data["is_bruteforce"] = True
                    self.stats["threat_types"]["ssh_bruteforce"] += 1
            except UnicodeDecodeError:
                ssh_data["is_encrypted"] = True

        self._queue_event(self.sio.emit("ssh_activity", ssh_data))

    def _detect_common_threats(self, packet: Packet):
        """Comprehensive threat detection"""
        # Port scan detection
        if packet.haslayer(TCP) and packet[TCP].flags == 0x29:  # SYN scan
            self._create_alert(
                alert_type="Port Scan",
                severity="High",
                source_ip=packet[IP].src if packet.haslayer(IP) else None,
                description="SYN scan detected",
                metadata={
                    "destination_port": packet[TCP].dport,
                    "flags": str(packet[TCP].flags),
                },
            )

        # ARP spoofing detection
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
            if packet[Ether].src != packet[ARP].hwsrc:
                self._create_alert(
                    alert_type="ARP Spoofing",
                    severity="Critical",
                    source_ip=packet[ARP].psrc,
                    description="ARP cache poisoning attempt",
                    metadata={
                        "claimed_mac": packet[ARP].hwsrc,
                        "actual_mac": packet[Ether].src,
                    },
                )

        # DNS tunneling detection
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns = packet[DNSQR]
            if len(dns.qname) > 50:  # Long domain names
                self._create_alert(
                    alert_type="DNS Tunneling",
                    severity="Medium",
                    source_ip=packet[IP].src if packet.haslayer(IP) else None,
                    description="Possible DNS tunneling",
                    metadata={
                        "query": dns.qname.decode(errors="replace"),
                        "length": len(dns.qname),
                    },
                )

    def _create_alert(
        self,
        alert_type: str,
        severity: str,
        source_ip: str,
        description: str,
        metadata: Dict = None,
    ):
        """Create and emit security alert with database logging"""
        alert_id = f"alert_{datetime.utcnow().timestamp()}_{hash(source_ip or '')}"
        alert = {
            "id": alert_id,
            "type": alert_type,
            "severity": severity,
            "source_ip": source_ip,
            "timestamp": datetime.utcnow().isoformat(),
            "description": description,
            "metadata": metadata or {},
        }

        # Update stats
        self.stats["alerts"].append(alert)
        self.stats["threat_types"][alert_type] += 1

        # Emit via Socket.IO
        self._queue_event(self.sio.emit("security_alert", alert))

        # Log to database
        self._queue_event(self._log_threat_to_db(alert))

    async def _log_threat_to_db(self, alert: Dict):
        """Log threat to database"""
        try:
            db = next(get_db())
            db.add(
                ThreatLog(
                    id=alert["id"],
                    rule_id=alert.get("rule_id", "heuristic"),
                    source_ip=alert["source_ip"],
                    threat_type=alert["type"],
                    severity=alert["severity"],
                    description=alert["description"],
                    raw_data=str(alert["metadata"]),
                    timestamp=datetime.fromisoformat(alert["timestamp"]),
                )
            )
            db.commit()
        except Exception as e:
            logger.error(f"Failed to log threat: {str(e)}")
            await self.sio.emit(
                "database_error",
                {
                    "operation": "threat_logging",
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )

    async def _log_packet_to_db(self, packet_data: dict):
        """Enhanced packet logging with safe model validation"""
        try:
            valid_fields = self.get_model_fields(Packets)
            filtered_data = {
                k: v for k, v in packet_data.items()
                if k in valid_fields
            }
            
            if not filtered_data:
                logger.warning("No valid fields found for packet")
                return

            async with get_db() as session:
                packet = Packets(**filtered_data)
                session.add(packet)
                await session.commit()
                
        except Exception as e:
            logger.error(f"Logging failed: {str(e)}")
        
    def start(self, interface: str = None):
        """Start sniffing with enhanced error handling"""
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            logger.warning("Sniffer already running")
            return

        if not interface:
            interface = conf.iface

        self.stop_event.clear()
        self.sniffer_thread = Thread(
            target=self._start_sniffing,
            args=(interface,),
            daemon=True,
            name="PacketSniffer",
        )
        self.sniffer_thread.start()
        logger.info(f"Started packet sniffing on interface {interface}")

        # Send system alert
        self._queue_event(
            self.sio.emit(
                "system_status",
                {
                    "component": "packet_sniffer",
                    "status": "running",
                    "interface": interface,
                    "timestamp": datetime.utcnow().isoformat(),
                },
            )
        )

    def _start_sniffing(self, interface: str):
        """Internal sniffing method with BPF filter"""
        try:
            # Basic BPF filter to ignore some noise
            bpf_filter = "not (dst net 127.0.0.1 or multicast or ip6)"

            sniff(
                iface=interface,
                prn=self._packet_handler,
                stop_filter=lambda _: self.stop_event.is_set(),
                store=False,
                filter=bpf_filter,
                promisc=True,
                
            )
        except Exception as e:
            logger.error(f"Sniffing error: {str(e)}")
            self._queue_event(
                self.sio.emit(
                    "system_error",
                    {
                        "component": "packet_capture",
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                )
            )
            self.stop()

    def get_stats(self) -> Dict:
        """Get comprehensive statistics"""
        uptime = (datetime.utcnow() - self.stats["start_time"]).total_seconds()

        return {
            **self.stats,
            "uptime_seconds": uptime,
            "avg_packets_per_second": (
                self.stats["total_packets"] / uptime if uptime > 0 else 0
            ),
            "current_time": datetime.utcnow().isoformat(),
        }

    def clear_stats(self):
        """Reset statistics while preserving runtime"""
        self.stats.update(
            {
                "total_packets": 0,
                "protocols": defaultdict(int),
                "top_talkers": defaultdict(int),
                "alerts": deque(maxlen=1000),
                "throughput": {"1min": deque(maxlen=60), "5min": deque(maxlen=300)},
                "threat_types": defaultdict(int),
            }
        )

    def register_http_listener(self, fn: Callable[[Dict], bool]):
        """
        Register a callback that returns False if it wants to block the packet,
        or True to let it through / continue processing.
        """
        self._http_listeners.append(fn)
