import re
import math
import json
import time
import logging
import platform
from operator import itemgetter
import asyncio 
from functools import lru_cache
from datetime import datetime, timedelta
from collections import defaultdict, deque, Counter
from typing import Callable, Dict, Optional, List, Tuple,Any
from multiprocessing import Process,Manager, Value,Queue, Event, Lock as ProcessLock
from pathlib import Path
import pickle 
import socket
import multiprocessing as mp
from multiprocessing.managers import DictProxy
from multiprocessing.queues import Full, Empty
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms

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
    AsyncSniffer,
    wrpcap
)
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.packet import Packet
import scapy.layers.http as HTTP
from scapy.layers.inet6 import IPv6ExtHdrFragment
import ipaddress
from sqlalchemy.inspection import inspect
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

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
from .reporter_helper import _reporter_loop, default_asn, default_geo
from ..ips.engine import IPSEngine

# Configure logging
logger = logging.getLogger("packet_sniffer")
logger.setLevel(logging.INFO)

from .utils.constants import BASE64_CHARS, cipher_name,SCORING_WEIGHTS,WEAK_CIPHERS,RECOMMENDED_CIPHERS,KNOWN_SERVICES  

class PacketSniffer:
    def __init__(self, sio_queue: Queue):

        self.sio_queue = sio_queue
        self._http_listeners: list[Callable[[Dict], bool]] = []
        self.manager = Manager()
        self.packet_counter = mp.Value("i", 0)
        self._setup_logging()
        self.stop_event = mp.Event()
        # self.recorder = PacketRecorder()
        self._running = False
        self.firewall_lock = mp.Lock()
        self.start_time = time.time()
        self.end_time = time.time()
        self._state_checked = False

        # Initialize queues and locks
        self.event_queue = Queue(maxsize=10000)
        self.data_lock = mp.Lock()
        self.processing_lock = self.manager.Lock()
        self.worker_process: Optional[Process] = None
        self.sniffer_process: Optional[Process] = None
        self._queue_monitor_active = False
        self._queue_stats = {"processed": 0, "dropped": 0, "errors": 0}

        self.last_request_time = {}

        self._async_sniffer: AsyncSniffer | None = None

        # Initialize shared data structures
        self.byte_distribution = [0] * 256  # For payload byte analysis
        self.service_map = defaultdict(int)
        self.rate_limiter = RateLimiter(
            max_requests=500, time_window=timedelta(seconds=60)
        )

        self.signature_engine = SignatureEngine(sio_queue)
        self.firewall = FirewallManager(sio_queue)

        # Initialize statistics
        self.stats = self.manager.dict({
        "start_time": datetime.utcnow(),  # datetime is immutable, so it's okay as-is
        "total_packets": 0,  # primitives like int are fine
        "protocols": self.manager.dict(),  # use manager.dict in place of defaultdict
        "flows":self.manager.dict(),
        "top_talkers": self.manager.dict(),
        "alerts": self.manager.list(),  # no maxlen, you'll need to manage length manually
        "throughput": self.manager.dict({
            "1min":self. manager.list(),  # again, no maxlen—handle it in logic
            "5min": self.manager.list()
        }),
        "geo_data": self.manager.dict(),
        "threat_types": self.manager.dict(),
    })
        self._last_seen_times = defaultdict(float)
        self._dns_counter = self.manager.dict()
        self._endpoint_tracker = defaultdict(lambda: defaultdict(set))
        self._protocol_counter = self.manager.dict()

        self.recent_packets = defaultdict(lambda: deque(maxlen=100))
        self.current_packet_source = None
        self.port_scan_detector = PortScanDetector()
        
        self._init_ip_databases()
        
        # RFC compliance patterns
        self.rfc7230_methods = {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE'}
        self.http_version_pattern = re.compile(r'HTTP/\d\.\d$')
        self.pseudo_headers = {':method', ':path', ':authority', ':scheme', ':status'}
        self.h2c_cleartext_ports = {80, 8080}  # HTTP/2 over TCP ports

        # Network path analysis cache
        self.network_path_cache = defaultdict(deque)

        # Start worker processes

        self._reporter_stop = Event()
        self.reporter_process = Process(
            target=_reporter_loop,
            args=(self.sio_queue, self.stats, self._reporter_stop,5.0),
            daemon=True,
        )

        # self.worker_process.start()
        # self.reporter_process.start()

    def __getstate__(self):
        # 1) Copy everything
        state = self.__dict__.copy()

        # 2) Strip known un-picklables by name
        for bad in (
            "manager",
            "worker_process",
            "sniffer_process",
            "reporter_process",
            "signature_engine",
            "firewall",
            "ids_signature_engine",
            "ips_engine",
            "blocker",
            "monitor",
            "_dns_counter",
            "_endpoint_tracker",
            "recent_packets",
        ):
            state.pop(bad, None)

        # 3) Strip any leftover Process objects by type
        for k, v in list(state.items()):
            if isinstance(v, mp.process.BaseProcess):
                state.pop(k)

        # 4) If already scanned, short‑circuit
        if self._state_checked:
            return state

        # 5) One‑time pickle test for anything else
        for k, v in list(state.items()):
            try:
                pickle.dumps(v)
            except Exception as e:
                print(f"❌ Cannot pickle attribute: {k} ({type(v)}) – {e}")
                state.pop(k)

        # 6) Mark done so we don’t repeat
        self._state_checked = True
        return state

    def _init_ip_databases(self):
        """Initialize local IP information databases"""
        self.asn_db = defaultdict(default_asn)
        self.geo_db = defaultdict(default_geo)

        
        # Load local IP data (example - extend with actual data)
        self._load_sample_data()

    def _load_sample_data(self):
        """Load sample IP data (replace with real data import)"""
        self.asn_db['8.8.8.8'] = {'asn': 15169, 'org': 'Google LLC'}
        self.geo_db['8.8.8.8'] = {'country': 'United States', 'city': 'Mountain View'}

    def get_queue_stats(self):
        """Return current queue statistics"""
        return {
            **self._queue_stats,
            "qsize": self.sio_queue.qsize(),
            "active": self._queue_monitor_active}

    def _update_traffic_baseline(self, http_data: Dict) -> None:
        """Update traffic baselines with rolling window statistics"""
        try:
            with self.data_lock:
                # Initialize if not exists
                if '1min' not in self.stats['throughput']:
                    self.stats['throughput']['1min'] = deque(maxlen=300)
                
                entry = {
                    'timestamp': time.time(),
                    'bytes': http_data['network_metrics']['packet_size'],
                    'packets': 1,
                    'source_ip': http_data['source_ip'],
                    'destination_ip': http_data['destination_ip']
                }
                
                self.stats['throughput']['1min'].append(entry)
                self._update_derived_metrics(entry)

        except Exception as e:
            logger.error(f"Traffic baseline update failed: {str(e)}", exc_info=True)
            self.sio_queue.put(('system_error', {
                'error': 'traffic_baseline_failure',
                'message': str(e)
            }))
    def _update_derived_metrics(self, entry: Dict) -> None:
        """Update derived network metrics in a thread-safe manner"""
        with self.data_lock:
            # Update top talkers
            self.stats['top_talkers'][entry['source_ip']] += entry['packets']
            self.stats['top_talkers'][entry['destination_ip']] += entry['packets']
            
            # Update protocol distribution
            protocol = entry.get('protocol', 'unknown')
            self.stats['protocols'][protocol] += 1
                   
    
    def _check_rfc_compliance(self, http_layer) -> Dict:
        """Verify HTTP protocol compliance with RFC standards"""
        compliance = {
            'rfc7230': {'valid': True, 'violations': []},
            'rfc7540': {'valid': False, 'violations': []}
        }

        try:
            # RFC 7230 (HTTP/1.1) checks
            if hasattr(http_layer, 'Method'):
                method = http_layer.Method.decode('ascii', errors='replace').strip()
                if method not in self.rfc7230_methods:
                    compliance['rfc7230']['violations'].append(f'Invalid method {method}')
                
            if hasattr(http_layer, 'Http_Version'):
                version = http_layer.Http_Version.decode('ascii', errors='replace').strip()
                if not self.http_version_pattern.match(version):
                    compliance['rfc7230']['violations'].append(f'Invalid version {version}')
            
            # RFC 7540 (HTTP/2) checks
            if hasattr(http_layer, 'Headers'):
                headers = http_layer.headers
                h2_indicators = sum(1 for h in headers if h.startswith(':'))
                if h2_indicators > 0:
                    compliance['rfc7540']['valid'] = True
                    for header in headers:
                        if header.startswith(':') and header not in self.pseudo_headers:
                            compliance['rfc7540']['violations'].append(f'Invalid pseudo-header {header}')
            
            # Check for HTTP/2 over TCP (h2c) compliance
            if compliance['rfc7540']['valid']:
                port = http_layer.get('Destination-Port', 80)
                if port not in self.h2c_cleartext_ports:
                    compliance['rfc7540']['violations'].append('Invalid port for h2c')

            # Update validity status
            compliance['rfc7230']['valid'] = len(compliance['rfc7230']['violations']) == 0
            compliance['rfc7540']['valid'] = len(compliance['rfc7540']['violations']) == 0

        except Exception as e:
            logger.warning(f"RFC compliance check failed: {str(e)}")
            self.sio_queue.put(('detection_error', {
                'error': 'rfc_check_failure',
                'message': str(e)
            }))

        return compliance
    
    def _analyze_network_path(self, source_ip: str) -> Dict:
        """Perform network path analysis using local data"""
        result = {
            'hops': [],
            'geo_path': [],
            'asn': self.asn_db[source_ip]['asn'],
            'org': self.asn_db[source_ip]['org'],
            'country': self.geo_db[source_ip]['country'],
            'city': self.geo_db[source_ip]['city']
        }

        try:
            # Reverse DNS lookup
            hostname = socket.gethostbyaddr(source_ip)[0]
            result['hostname'] = hostname
        except (socket.herror, socket.gaierror):
            result['hostname'] = 'unknown'

        # Add cached traceroute information
        result['hops'] = list(self.network_path_cache.get(source_ip, deque(maxlen=10)))
        
        return result
    
    
    def _get_asn_info(self, ip_address: str) -> Dict:
        """Retrieve ASN information from local database"""
        return self.asn_db[ip_address]

    def _store_network_path(self, source_ip: str, hops: list):
        """Store network path information in cache"""
        self.network_path_cache[source_ip].extend(hops)
        if len(self.network_path_cache[source_ip]) > 10:
            self.network_path_cache[source_ip].popleft()
       
    def _setup_logging(self):
        """Configure packet-level logging"""
        self.packet_logger = logging.getLogger("packet_traffic")
        self.packet_logger.setLevel(logging.INFO)

    def _periodic_reporter(self):
        """Periodically report system stats with interrupt handling"""
        while not self.stop_event.is_set():
            try:
                time.sleep(60)
                stats = self._report_system_stats()
                self.sio_queue.put(("system_stats", stats))
            except KeyboardInterrupt:
                logger.debug("Reporter received KeyboardInterrupt")
                break
            except Exception as e:
                logger.error("Reporter error: %s", str(e))

    def _report_system_stats(self):
        """Send periodic system statistics"""
        stats = {
            "timestamp": datetime.utcnow().isoformat(),
            "packets_per_minute": sum(self.stats["throughput"]["1min"]),
            "top_talkers" : dict(
                sorted(
                    self.stats["top_talkers"].items(),
                    key=itemgetter(1),
                    reverse=True
                )[:10]
            ),
            "threat_distribution": dict(self.stats["threat_types"]),
            "queue_stats": self.get_queue_stats(),
            "memory_usage": self._get_memory_usage(),
            "cpu_usage": self._get_cpu_usage(),
        }
        self.sio_queue.put(("system_stats", stats))
        return stats

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

    def _queue_event(self, event_type: str, data: dict):
        if not self._running:
            return

        event = ("packet_sniffer", event_type, data)
        try:
            self.sio_queue.put_nowait(event)
        except Full:
            logger.warning("Dropped event due to full queue: %s", event_type)
            with self.data_lock:
                self._queue_stats["dropped"] += 1

    def _process_queue(self):
        """Process events from the queue in a dedicated process"""
        while not self.stop_event.is_set():
            try:
                event = self.event_queue.get(timeout=1)

                if callable(event):
                    event()
                elif isinstance(event, tuple) and len(event) == 2:
                    self.sio_queue.put(event)
                else:
                    logger.error("Malformed event: %s", str(event))

            except Empty:
                continue
            except KeyboardInterrupt:
                logger.debug("Queue processor received KeyboardInterrupt")
                break  # Exit loop on interrupt
            except Exception as e:
                logger.error("Queue processing error: %s", str(e))
                continue

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
        """Enhanced protocol detection with comprehensive port support"""
        try:
            # Define common protocol-port mappings
            TCP_PROTOCOLS = {
                80: "HTTP",
                8080: "HTTP",
                8008: "HTTP",
                8000: "HTTP",
                8888: "HTTP",
                443: "HTTPS",
                8443: "HTTPS",
                832: "HTTPS",
                8081: "HTTPS",
                22: "SSH",
                21: "FTP",
                25: "SMTP",
                587: "SMTP",
                465: "SMTPS",
                23: "Telnet",
                53: "DNS-TCP",
                3306: "MySQL",
                5432: "PostgreSQL",
                27017: "MongoDB",
                3389: "RDP",
                5900: "VNC"
            }

            UDP_PROTOCOLS = {
                53: "DNS",
                67: "DHCP",
                68: "DHCP",
                69: "TFTP",
                123: "NTP",
                161: "SNMP",
                162: "SNMPTRAP",
                500: "ISAKMP",
                514: "SYSLOG",
                520: "RIP",
                1900: "SSDP",
                3478: "STUN",
                5349: "TURN",
                5060: "SIP",
                1194: "OpenVPN"
            }

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                # Check both source and destination ports
                return TCP_PROTOCOLS.get(tcp.dport) or \
                    TCP_PROTOCOLS.get(tcp.sport) or \
                    "TCP"

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                return UDP_PROTOCOLS.get(udp.dport) or \
                    UDP_PROTOCOLS.get(udp.sport) or \
                    "UDP"

            elif packet.haslayer(ICMP):
                return "ICMP"

            elif packet.haslayer(ARP):
                return "ARP"

            elif packet.haslayer(Dot11):
                return "802.11"

            elif packet.haslayer(PPPoE):
                return "PPPoE"

            elif packet.haslayer(DNS):
                return "DNS"  # Fallback for DNS detection

            elif packet.haslayer(HTTP):
                return "HTTP"  # Fallback for HTTP detection
            return "Other"

        except Exception as e:
            logger.debug(f"Protocol detection error: {str(e)}")
            return "Unknown"

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
                "window_ratio": tcp.window / (len(packet) if len(packet) > 0 else 1),
            },
        }

    def _packet_handler(self, packet: Packet):
        """Main packet processing method with enhanced analysis"""
        
        self.start_time = time.perf_counter()
        # self.recorder.handle_packet(packet)
        

        with self.packet_counter.get_lock():
            self.packet_counter.value += 1

        try:
            with self.processing_lock:
                src_ip = dst_ip = None
                ip_version = None

                # Extract IP information first with validation
                try:
                    if packet.haslayer(IP):
                        ip_version = 4
                        src_ip = str(packet[IP].src)
                        dst_ip = str(packet[IP].dst)
                    elif packet.haslayer(IPv6):
                        ip_version = 6
                        src_ip = str(packet[IPv6].src)
                        dst_ip = str(packet[IPv6].dst)
                except Exception as e:
                    logger.debug("IP layer extraction error: %s", str(e))
                    return

                # Create packet_info with validated IPs
                packet_info = {
                    "timestamp": datetime.utcnow(),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "ip_version": ip_version,
                    "src_port": None,
                    "dst_port": None,
                    "protocol": "Unknown",  # Default value
                    "size": len(packet),
                    "flags": None,
                    "payload": None,
                    "dns_query": None,
                    "http_method": None,
                    "http_path": None,
                }

                # Safely get protocol name with error handling
                try:
                    packet_info["protocol"] = self._get_protocol_name(packet)
                except Exception as e:
                    logger.debug("Protocol detection error: %s", str(e))
                    packet_info["protocol"] = "Unknown"

                # Validate essential fields before proceeding
                if not self._validate_packet(packet_info):
                    return

                try:
                    if packet.haslayer(IP):
                        self.current_packet_source = packet[IP].src
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                    elif packet.haslayer(IPv6):
                        self.current_packet_source = packet[IPv6].src
                        src_ip = packet[IPv6].src
                        dst_ip = packet[IPv6].dst
                except Exception as e:
                    logger.debug("IP source/dest extraction error: %s", str(e))
                    return

                # Service mapping with layer safety
                if packet.haslayer(TCP):
                    try:
                        self.service_map[packet[TCP].dport] += 1
                        packet_info.update({
                            "src_port": packet[TCP].sport,
                            "dst_port": packet[TCP].dport,
                            "flags": str(packet[TCP].flags) if hasattr(packet[TCP], 'flags') else None
                        })
                    except Exception as e:
                        logger.debug("TCP layer processing error: %s", str(e))

                # Byte distribution analysis with safety
                if packet.haslayer(Raw):
                    try:
                        raw_layer = packet[Raw]
                        packet_info["payload"] = raw_layer.load.hex() if hasattr(raw_layer, 'load') else None
                        if raw_layer.load:
                            for byte in bytes(raw_layer.load):
                                self.byte_distribution[byte] += 1
                    except Exception as e:
                        logger.debug("Raw payload processing error: %s", str(e))

                # Core processing with multiprocessing-safe updates
                try:
                    with self.data_lock:
                        self.stats["total_packets"] += 1
                        self.stats["protocols"][packet_info["protocol"]] += 1
                        self.stats["throughput"]["1min"].append(1)
                        self.stats["throughput"]["5min"].append(1)
                except Exception as e:
                    logger.debug("Stats update error: %s", str(e))

                # Layer 3+ analysis with error protection
                try:
                    if packet.haslayer(IP):
                        with self.data_lock:
                            try:
                                self.recent_packets[src_ip].append({
                                    "timestamp": time.time(),
                                    "protocol": packet_info["protocol"],
                                    "dst_ip": dst_ip,
                                    "dst_port": (packet[TCP].dport if packet.haslayer(TCP)
                                                else packet[UDP].dport if packet.haslayer(UDP) 
                                                else None),
                                    "length": len(packet),
                                })
                                self._protocol_counter[src_ip][packet_info["protocol"]] += 1
                            except Exception as e:
                                logger.debug("Recent packets update error: %s", str(e))

                        self._analyze_ip_packet(packet[IP])
                    elif packet.haslayer(IPv6):
                        self._analyze_ipv6_packet(packet[IPv6])
                except Exception as e:
                    logger.debug("Layer 3+ analysis error: %s", str(e))

                # Application layer analysis with safety
                try:
                    http_layer = None
                    if packet.haslayer(HTTPRequest):
                        http_layer = packet[HTTPRequest]
                    elif packet.haslayer(HTTPResponse):
                        http_layer = packet[HTTPResponse]

                    if http_layer:
                        try:
                            packet_info.update({
                                "http_method": self._safe_extract(http_layer, 'Method'),
                                "http_path": self._safe_extract(http_layer, 'Path')
                            })
                            self._analyze_http(packet)
                        except Exception as e:
                            logger.debug("HTTP analysis error: %s", str(e))
                    elif packet.haslayer(DNSQR):
                        try:
                            dns = packet[DNSQR]
                            raw_qname = self._safe_extract(dns, "qname")

                            # Sanitize and trim the query
                            sanitized_qname = self._sanitize_dns_query(raw_qname, max_length=255)

                            packet_info["dns_query"] = sanitized_qname

                            logger.info("DNS Query: %s (Type:%s) from %s", 
                                        sanitized_qname, 
                                        dns.qtype, 
                                        src_ip)
                            self._analyze_dns(packet)
                        except Exception as e:
                            logger.debug("DNS analysis error: %s", str(e))
                    elif packet.haslayer(TCP) and (packet[TCP].dport == 22 or packet[TCP].sport == 22):
                        try:
                            self._endpoint_tracker[src_ip]["tcp"].add((dst_ip, packet[TCP].dport))
                            self._analyze_ssh(packet)
                        except Exception as e:
                            logger.debug("SSH analysis error: %s", str(e))
                except Exception as e:
                    logger.debug("Application layer processing error: %s", str(e))

                # Threat detection with safety
                try:
                    self._detect_common_threats(packet)
                    if packet.haslayer(HTTPRequest):
                        try:
                            http = packet[HTTPRequest]
                            logger.info("HTTP %s %s%s from %s",
                                        http.Method.decode(errors='replace'),
                                        http.Host.decode(errors='replace'),
                                        http.Path.decode(errors='replace'),
                                        src_ip)
                        except Exception as e:
                            logger.debug("HTTP logging error: %s", str(e))
                except Exception as e:
                    logger.debug("Threat detection error: %s", str(e))

                # UDP handling with safety
                if packet.haslayer(UDP):
                    try:
                        self._endpoint_tracker[src_ip]["udp"].add((dst_ip, packet[UDP].dport))
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport
                        })
                    except Exception as e:
                        logger.debug("UDP processing error: %s", str(e))

                # Final validation before logging
                if not packet_info['src_ip'] or not packet_info['dst_ip']:
                    logger.debug("Skipping non-IP packet: %s", packet.summary())
                    return

                if not self._final_validation(packet_info):
                    logger.debug("Invalid packet format: %s", packet.summary())
                    return

                logger.debug("Valid packet ready for DB: %s", packet_info)
                try:
                    self._log_packet_to_db(packet_info)
                except Exception as e:
                    logger.error("Database logging error: %s", str(e))
                logger.info("Found packet: %s", packet_info)
            self.sio_queue.put(("packet_data", packet_info))
            
        except Exception as e:
            logger.error("Packet processing error: %s", str(e))
            self.sio_queue.put(
                (
                    "system_error",
                    {
                        "component": "packet_handler",
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                )
            )
        finally:
            with self.processing_lock:
                self.current_packet_source = None

    def _is_binary(self, data: bytes) -> bool:
        """Check if data appears to be binary"""
        if not data:
            return False
        return bool(re.search(rb'[\x00-\x08\x0b-\x0c\x0e-\x1f]', data))

    def _smart_truncate(self, text: str, max_length: int) -> str:
        """Truncate text while trying to preserve domain structure"""
        if '.' in text:
            parts = text.split('.')
            while len('.'.join(parts)) > max_length and len(parts) > 1:
                parts.pop(0)
            truncated = '.'.join(parts)
            if len(truncated) > max_length:
                return '...' + truncated[-(max_length-3):]
            return truncated
        return text[:max_length-3] + '...'

    def _sanitize_dns_query(self, query: bytes, max_length: int = 255) -> str:
        """Sanitize DNS query with length trimming and binary detection"""
        try:
            # Decode with error handling and truncation
            decoded = query.decode('utf-8', errors='replace').strip()
        except UnicodeDecodeError:
            # Fallback to Latin-1 if UTF-8 fails
            decoded = query.decode('latin-1', errors='replace').strip()

        # Detect binary-looking payloads
        if self._is_binary(query):
            hex_repr = query.hex()[:max_length]
            return f"[BINARY:{hex_repr}]..."

        # Trim long queries while preserving structure
        if len(decoded) > max_length:
            return self._smart_truncate(decoded, max_length)

        return decoded

    def _validate_packet(self, packet_info: dict) -> bool:
        """Perform comprehensive packet validation"""
        validation_checks = [
            (packet_info["src_ip"], "src_ip"),
            (packet_info["dst_ip"], "dst_ip"),
            (packet_info["protocol"], "protocol"),
            (packet_info["size"] >= 0, "size"),
        ]

        for value, field in validation_checks:
            if not value:
                logger.debug(f"Invalid {field} in packet: {value}")
                return False

        try:
            if packet_info["src_ip"]:
                ipaddress.ip_address(packet_info["src_ip"])
            if packet_info["dst_ip"]:
                ipaddress.ip_address(packet_info["dst_ip"])
        except ValueError as e:
            logger.warning("Invalid IP format: %s", str(e))
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
            p_x = float(data.count(x)) / data
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return entropy

    def _analyze_ip_packet(self, ip_packet):
        """Analyze IPv4 packets"""
        src_ip = ip_packet.src
        dst_ip = ip_packet.dst

        # Update top talkers
        with self.data_lock:
            self.stats["top_talkers"][src_ip] += 1
            self.stats["top_talkers"][dst_ip] += 1

        # Rate limiting
        if self.rate_limiter.check_rate_limit(src_ip):
            with self.firewall_lock:
                self.firewall.block_ip(
                src_ip, "Rate limit exceeded", duration=3600
            )
            data = {
                "source_ip": src_ip,
                "reason": "Rate limit exceeded",
                "duration":36000
            }

            self.sio_queue.put(( "firewall_blocked",data))

    def _analyze_ipv6_packet(self, ipv6_packet):
        """Enhanced IPv6 threat analysis with tunneling detection"""
        src_ip = ipv6_packet.src
        dst_ip = ipv6_packet.dst

        # Update statistics
        with self.data_lock:
            self.stats["top_talkers"][src_ip] = (
                self.stats["top_talkers"].get(src_ip, 0) + 1
            )

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

        self.sio_queue.put(("ipv6_activity", ipv6_data))

        # Critical threat response
        if threats["tunneling_suspected"]:
            alert =  {
                        "type": "IPv6 Tunneling Attempt",
                        "severity": "high",
                        "source_ip": src_ip,
                        "description": f"Potential IPv6 tunneling detected from {src_ip}",
                    }
            self._queue_event("security_alert", alert)
            self.sio_queue.put_nowait(("security_alert", alert))

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
        with self.processing_lock:
            if not self.current_packet_source:
                logger.debug("Missing source context for NXDOMAIN ratio")
                return 0.0

            counter = self._dns_counter.get(
                self.current_packet_source, {"total": 0, "nxdomain": 0}
            )
            total = counter["total"]
        return round(counter["nxdomain"] / total, 4) if total > 0 else 0.0

    def _calculate_inter_arrival(self, packet: Packet) -> float:
        """Calculate time between consecutive packets from same source"""

        if not packet.haslayer(IP):
            return 0.0

        src_ip = packet[IP].src
        current_time = time.time()

        with self.data_lock:
            last_time = self._last_seen_times.get(src_ip, current_time)
            interval = current_time - last_time
            self._last_seen_times[src_ip] = current_time

        return round(interval, 6)

    def _get_protocol_ratio(self, src_ip: str) -> dict:
        """Get protocol distribution ratios for a source IP"""
        with self.data_lock:
            counter = self._protocol_counter.get(src_ip, Counter())
            total = sum(counter.values())

            if total == 0:
                return {}

            return {proto: count / total for proto, count in counter.most_common()}

    def _get_unique_endpoints(self, src_ip: str) -> dict:
        """Get unique destination endpoints for a source IP"""
        with self.data_lock:
            endpoints = self._endpoint_tracker.get(src_ip, {})

            # Debug: print the actual data
            logger.debug("endpoints for %s: %s", src_ip, endpoints)

            # If there is data, check port types
            if endpoints:
                for proto, ports in endpoints.items():
                    logger.debug(
                        "Protocol: %s, Ports: %s, Port types: %s", proto, ports, [type(p) for p in ports]
                    )

            return {
                "total": sum(len(ports) for ports in endpoints.values()),
                "per_protocol": {
                    proto: len(ports) for proto, ports in endpoints.items()
                },
            }

    
    def _analyze_http(self, packet: Packet):
        """Comprehensive HTTP analysis with advanced threat detection"""
        try:
            # Layer extraction with safety checks
            http_layer = None
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
            elif packet.haslayer(HTTPResponse):
                http_layer = packet[HTTPResponse]

            if not http_layer:
                return

            # Payload extraction with error handling
            try:
                payload = self._extract_http_payload(packet)
            except Exception as e:
                logger.error(f"Payload extraction failed: {str(e)}", exc_info=True)
                payload = b''

            # Base HTTP data structure
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
                "observability_metrics": {},
            }

            # Flow tracking with multiprocessing-safe locks
            flow_info = {}
            try:
                with self.data_lock:
                    current_time = time.time()
                    tcp_layer = packet[TCP] if packet.haslayer(TCP) else None
                    flow_key = (
                        http_data["source_ip"],
                        http_data["destination_ip"],
                        tcp_layer.sport if tcp_layer else None,
                        tcp_layer.dport if tcp_layer else None,
                    )
                    
                    if flow_key not in self.stats["flows"]:
                        self.stats["flows"][flow_key] = {
                            "first_seen": current_time,
                            "last_seen": current_time,
                            "packet_count": 1,
                            "byte_count": len(packet),
                            "direction": "outbound" if http_data["source_ip"] == self.current_packet_source else "inbound",
                        }
                    else:
                        self.stats["flows"][flow_key].update({
                            "last_seen": current_time,
                            "packet_count": self.stats["flows"][flow_key]["packet_count"] + 1,
                            "byte_count": self.stats["flows"][flow_key]["byte_count"] + len(packet),
                        })

                    flow_info = self.stats["flows"][flow_key]
                    flow_duration = flow_info["last_seen"] - flow_info["first_seen"]
                    bytes_per_second = flow_info["byte_count"] / flow_duration if flow_duration > 0 else 0
                    packets_per_second = flow_info["packet_count"] / flow_duration if flow_duration > 0 else 0
            except Exception as e:
                logger.error(f"Flow tracking failed: {str(e)}", exc_info=True)
                self.sio_queue.put(('system_error', {
                    'error': 'flow_tracking_failed',
                    'message': str(e),
                    'source_ip': http_data.get("source_ip")
                }))
                flow_duration = 0
                bytes_per_second = 0
                packets_per_second = 0

            # Network layer extraction with safety
            ip_layer = packet[IP] if packet.haslayer(IP) else None
            tcp_layer = packet[TCP] if packet.haslayer(TCP) else None
            
            # Header analysis
            header_fields = http_layer.fields if http_layer else {}
            try:
                header_length = sum(len(str(k)) + len(str(v)) for k, v in header_fields.items())
            except:
                header_length = 0

            # Main data structure population
            http_data.update({
                "network_metrics": {
                    "packet_size": len(packet),
                    "inter_arrival_time": self._calculate_inter_arrival(packet),
                    "protocol_ratio": self._get_protocol_ratio(packet[IP].src) if packet.haslayer(IP) else 0,
                    "protocol": ip_layer.proto if ip_layer else None,
                    "source_port": tcp_layer.sport if tcp_layer else None,
                    "destination_port": tcp_layer.dport if tcp_layer else None,
                    "ttl": ip_layer.ttl if ip_layer else None,
                    "packets_sent": self.stats["top_talkers"].get(http_data["source_ip"], 0),
                    "packets_received": self.stats["top_talkers"].get(http_data["destination_ip"], 0),
                    "bytes_per_second": round(bytes_per_second, 2),
                    "packets_per_second": round(packets_per_second, 2),
                    "unique_endpoints": self._get_unique_endpoints(packet[IP].src) if packet.haslayer(IP) else 0,
                    "tcp_metrics": self._analyze_tcp_metadata(packet),
                },
                "payload_characteristics": {
                    "entropy": self._calculate_entropy(payload),
                    "hex_patterns": self._find_hex_patterns(payload),
                    "header_length": header_length,
                    "compression_ratio": len(payload) / (header_length + 1) if payload else 0,
                    "header_field_count": len(header_fields),
                    "printable_ratio": sum(32 <= c < 127 for c in payload) / len(payload) if payload else 0,
                },
                "session_context": {
                    "request_count": self._get_session_count(packet[IP].src) if packet.haslayer(IP) else 0,
                    "unique_endpoints": self._get_unique_endpoints(packet[IP].src) if packet.haslayer(IP) else 0,
                    "flow_duration": round(flow_duration, 4),
                    "flow_id": hash(flow_key) if flow_key else None,
                    "direction": flow_info.get("direction", "unknown"),
                    "session_state": "new" if flow_info.get("packet_count", 0) == 1 else "established"
                }
            })

            # Advanced analyses with error handling
            try:
                http_data["header_analysis"] = {
                    "spoofed_headers": self._check_header_spoofing(http_layer),
                    "injection_vectors": self._detect_header_injections(http_layer),
                    "security_headers": self._check_security_headers(http_layer),
                    "header_manipulation": self._detect_header_tampering(http_layer),
                }

                http_data["content_analysis"] = {
                    "injection_patterns": self._detect_content_injections(payload),
                    "malicious_payloads": self._scan_malicious_patterns(payload),
                    "data_exfiltration": self._detect_payload_exfiltration(payload),
                    "path_exfiltration": self._detect_path_exfiltration(http_data["path"]),
                    "encoding_analysis": self._analyze_encodings(payload),
                }

                http_data["behavioral_indicators"] = {
                    "unusual_timing": self._check_request_timing(packet),
                    "beaconing": self._detect_beaconing(http_data),
                    "protocol_violations": self._check_protocol_anomalies(http_layer),
                }

                http_data["threat_analysis"] = self._calculate_threat_score(http_data)
            except Exception as e:
                logger.error(f"Advanced analysis failed: {str(e)}", exc_info=True)
                self.sio_queue.put(('system_error', {
                    'error': 'analysis_failed',
                    'message': str(e),
                    'source_ip': http_data.get("source_ip")
                }))

            # Threat detection and notification
            try:
                critical_threats = self._detect_critical_threats(http_data, payload)
                if critical_threats:
                    self.sio_queue.put((
                        "critical_alert",
                        {
                            **critical_threats,
                            "raw_packet_summary": packet.summary(),
                            "mitigation_status": "pending",
                        }
                    ))

                if payload:
                    sig_results = self.signature_engine.scan_packet(payload)
                    if sig_results:
                        self.sio_queue.put_nowait(
                            ("signature_match", {**sig_results, "context": http_data})
                        )

                self.sio_queue.put(("http_activity", http_data))
            except Exception as e:
                logger.critical(f"Notification failed: {str(e)}", exc_info=True)

        except Exception as e:
            logger.critical(f"HTTP analysis failed completely: {str(e)}", exc_info=True)
            self.sio_queue.put(('system_error', {
                'error': 'http_analysis_failed',
                'message': str(e),
                'packet_summary': packet.summary() if 'packet' in locals() else None
            }))
        
        
    def __analyze_chunked_encoding(self, payload: bytes) -> dict:
        """
        Internal method to validate chunked transfer encoding

        Args:
            payload: HTTP payload bytes

        Returns:
            dict: Chunked encoding validation results
        """
        results = {
            "invalid_chunks": 0,
            "incomplete_final_chunk": False,
            "chunk_size_errors": 0,
        }

        try:
            chunks = payload.split(b"\r\n\r\n", 1)[-1].split(b"\r\n")
            total_size = 0

            for i in range(0, len(chunks), 2):
                if i + 1 >= len(chunks):
                    results["incomplete_final_chunk"] = True
                    break

                size_line = chunks[i].strip()
                try:
                    chunk_size = int(size_line, 16)
                except ValueError:
                    results["chunk_size_errors"] += 1
                    continue

                if chunk_size == 0:
                    break

                total_size += chunk_size
                expected_length = len(chunks[i + 1])
                if expected_length != chunk_size:
                    results["invalid_chunks"] += 1

        except Exception as e:
            logger.debug(f"Chunked encoding analysis failed: {str(e)}")
            results["analysis_failed"] = True

        return results
    
    def _analyze_ciphersuites(self, packet: Packet) -> dict:
        """
        Analyze TLS cipher suites by manually parsing TCP payload
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Cipher suite information with security assessments
        """
        ciphers = {
            'supported_ciphers': [],
            'weak_ciphers': [],
            'recommended_ciphers': [],
            'tls_version': None,
            'analysis_error': False
        }

        try:
            if not packet.haslayer(TCP):
                return ciphers

            tcp = packet[TCP]
            if not tcp.payload:
                return ciphers

            # Get raw payload bytes
            raw = bytes(tcp.payload)
            if len(raw) < 5:
                return ciphers

            # Check TLS handshake (Content Type 0x16)
            if raw[0] != 0x16:
                return ciphers

            # Parse TLS version (bytes 1-3)
            version_bytes = raw[1:3]
            ciphers['tls_version'] = self.__parse_tls_version_from_bytes(version_bytes)

            # Look for Client Hello (Handshake Type 0x01)
            handshake_type = raw[5]
            if handshake_type != 0x01:  # Not ClientHello
                return ciphers

            # Parse cipher suites from ClientHello
            cipher_suites = self.__extract_cipher_suites(raw)
            ciphers['supported_ciphers'] = [self.__parse_cipher_suite(c) for c in cipher_suites]

            # Evaluate cipher strength
            ciphers['weak_ciphers'] = [c for c in ciphers['supported_ciphers'] 
                                    if c in WEAK_CIPHERS]
            ciphers['recommended_ciphers'] = [c for c in ciphers['supported_ciphers']
                                            if c in RECOMMENDED_CIPHERS]

        except Exception as e:
            logger.error(f"Cipher suite analysis failed: {str(e)}", exc_info=True)
            ciphers['analysis_error'] = True

        return ciphers


    
    def __extract_cipher_suites(self, raw: bytes) -> list:
        """Extract cipher suites from ClientHello message"""
        try:
            # ClientHello structure offsets
            pos = 5  # Start after TLS record header
            pos += 4  # Skip handshake message length
            pos += 2  # Skip client version
            pos += 32  # Skip random bytes
            session_id_length = raw[pos]
            pos += 1 + session_id_length
            
            # Skip cipher suites length (2 bytes)
            cipher_suites_length = int.from_bytes(raw[pos:pos+2], 'big')
            pos += 2
            
            # Extract cipher suite codes (2 bytes each)
            cipher_suites = []
            for _ in range(cipher_suites_length // 2):
                suite = raw[pos:pos+2]
                cipher_suites.append(suite)
                pos += 2
                
            return cipher_suites

        except IndexError:
            return []
    
    
    def __parse_cipher_suite(self, suite_bytes: bytes) -> str:
        """Convert cipher suite bytes to IANA name"""
        cipher_map = {
            b'\x00\x2f': 'TLS_RSA_WITH_AES_128_CBC_SHA',
            b'\x00\x35': 'TLS_RSA_WITH_AES_256_CBC_SHA',
            b'\xc0\x14': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
            b'\xc0\x2b': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
            b'\x13\x01': 'TLS_AES_128_GCM_SHA256',
            b'\x13\x02': 'TLS_AES_256_GCM_SHA384',
            b'\x00\x04': 'TLS_RSA_WITH_RC4_128_SHA',
            b'\x00\x0a': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        }
        return cipher_map.get(suite_bytes, f'UNKNOWN_{suite_bytes.hex().upper()}')


    
    def __parse_tls_version_from_bytes(self, version_bytes: bytes) -> str:
        """Parse TLS version from 2-byte version field"""
        version_map = {
            b'\x03\x04': 'TLS 1.3',
            b'\x03\x03': 'TLS 1.2',
            b'\x03\x02': 'TLS 1.1',
            b'\x03\x01': 'TLS 1.0',
            b'\x03\x00': 'SSL 3.0'
        }
        return version_map.get(version_bytes, f'Unknown ({version_bytes.hex()})')



    def _analyze_content_gaps(self, payload: bytes) -> dict:
        """
        Analyze payload for content inconsistencies and structural anomalies.

        Args:
            payload: Raw HTTP payload bytes

        Returns:
            dict: Structural integrity findings with severity scores
        """
        findings = {
            "header_body_mismatch": False,
            "chunked_errors": 0,
            "compression_anomalies": 0,
            "severity": 0.0,
        }

        try:
            if not payload:
                return findings

            # Check for chunked encoding inconsistencies
            if b"Transfer-Encoding: chunked" in payload:
                chunked_analysis = self.__analyze_chunked_encoding(payload)
                findings.update(chunked_analysis)

            # Check for Content-Length header mismatches
            content_length = self.__extract_content_length(payload)
            if content_length is not None:
                body_length = len(payload.split(b"\r\n\r\n", 1)[-1])
                if body_length != content_length:
                    findings["header_body_mismatch"] = True
                    findings["severity"] = max(findings["severity"], 0.7)

            # Check for suspicious compression patterns
            if b"Content-Encoding" in payload:
                findings["compression_anomalies"] = self.__check_compression_anomalies(
                    payload
                )

        except Exception as e:
            logger.error(f"Content gap analysis failed: {str(e)}", exc_info=True)
            findings["analysis_error"] = True

        return findings

    def __extract_content_length(self, payload: bytes) -> Optional[int]:
        """
        Safely extract and validate Content-Length header from HTTP payload
        
        Args:
            payload: Raw HTTP payload bytes
            
        Returns:
            int: Valid content length if found and valid, None otherwise
        """
        try:
            # Split headers from body
            headers_part = payload.split(b'\r\n\r\n', 1)[0]
            
            # Find Content-Length header
            for line in headers_part.split(b'\r\n'):
                if line.lower().startswith(b'content-length:'):
                    try:
                        # Split header key/value
                        _, value = line.split(b':', 1)
                        content_length = value.strip().decode('ascii')
                        
                        # Validate numeric value
                        if not content_length.isdigit():
                            logger.warning(f"Invalid Content-Length value: {content_length}")
                            return None
                            
                        # Convert to integer
                        length = int(content_length)
                        
                        # Check for multiple Content-Length headers
                        if b'content-length:' in line.lower().replace(line.lower(), b'', 1):
                            logger.warning("Multiple Content-Length headers detected")
                            return None
                            
                        # Validate against maximum realistic value
                        if length > 10**9:  # 1GB
                            logger.warning(f"Excessive Content-Length: {length}")
                            return None
                            
                        return length
                        
                    except (ValueError, UnicodeDecodeError) as e:
                        logger.debug(f"Content-Length parsing failed: {str(e)}")
                        return None
                        
            return None

        except Exception as e:
            logger.error(f"Content-Length extraction error: {str(e)}", exc_info=True)
            return None
    
    def __check_compression_anomalies(self, payload: bytes) -> dict:
        """
        Detect suspicious compression patterns in HTTP/TLS traffic
        
        Args:
            payload: Raw packet payload bytes
            
        Returns:
            dict: Compression findings with severity assessment
        """
        findings = {
            'tls_compression': [],
            'http_compression': None,
            'insecure_methods': [],
            'severity': 0.0
        }

        try:
            # ==================== TLS Compression Analysis ====================
            if len(payload) > 5 and payload[0] == 0x16:  # TLS handshake
                handshake_type = payload[5]
                pos = 5  # Start after TLS record header
                
                # Skip record header length
                record_length = int.from_bytes(payload[3:5], 'big')
                pos += 4 if record_length > 0x4000 else 3
                
                if handshake_type == 0x01:  # ClientHello
                    pos += 38  # Skip client version + random bytes
                    session_id_length = payload[pos]
                    pos += 1 + session_id_length
                    
                    # Skip cipher suites length
                    cipher_suites_length = int.from_bytes(payload[pos:pos+2], 'big')
                    pos += 2 + cipher_suites_length
                    
                    # Get compression methods
                    compression_methods_length = payload[pos]
                    pos += 1
                    findings['tls_compression'] = [
                        self.__parse_compression_method(m) 
                        for m in payload[pos:pos+compression_methods_length]]
                    
                elif handshake_type == 0x02:  # ServerHello
                    pos += 38  # Skip server version + random bytes
                    session_id_length = payload[pos]
                    pos += 1 + session_id_length
                    
                    # Get selected compression method
                    if len(payload) > pos:
                        findings['tls_compression'] = [
                            self.__parse_compression_method(payload[pos])]

                # Check insecure TLS compression
                insecure_tls_methods = {'DEFLATE', 'LZS'}
                for method in findings['tls_compression']:
                    if method in insecure_tls_methods:
                        findings['insecure_methods'].append(f'TLS_{method}')
                        findings['severity'] = max(findings['severity'], 0.8)

            # ==================== HTTP Compression Analysis ====================
            # Parse HTTP headers from payload
            http_headers = self.__parse_http_headers(payload)
            
            http_compression = {
                'content_encoding': http_headers.get('Content-Encoding', ''),
                'accept_encoding': http_headers.get('Accept-Encoding', ''),
                'transfer_encoding': http_headers.get('Transfer-Encoding', '')
            }
            findings['http_compression'] = http_compression
            
            # Detect compression mismatch
            if (http_compression['content_encoding'] and 
                not http_compression['accept_encoding']):
                findings['severity'] = max(findings['severity'], 0.6)
                findings['insecure_methods'].append('Forced-Compression')

            # Detect deprecated methods
            deprecated_methods = {'compress', 'deflate', 'gzip'}
            used_methods = {m.strip().lower() 
                            for m in http_compression['content_encoding'].split(',') + 
                                    http_compression['accept_encoding'].split(',')}
            
            findings['insecure_methods'].extend(
                m for m in used_methods if m in deprecated_methods
            )
            
            if findings['insecure_methods']:
                findings['severity'] = max(findings['severity'], 0.7)

        except Exception as e:
            logger.error(f"Compression analysis failed: {str(e)}", exc_info=True)
            findings['analysis_error'] = True

        return findings


    def __parse_compression_method(self, method_byte: int) -> str:
        """Convert TLS compression method byte to name"""
        methods = {
            0x00: 'NULL',
            0x01: 'DEFLATE',
            0x40: 'LZS',
            0xFF: 'reserved'
        }
        return methods.get(method_byte, f'UNKNOWN_0x{method_byte:02x}')

    def __parse_http_headers(self, payload: bytes) -> dict:
        """Extract HTTP headers from raw payload"""
        headers = {}
        try:
            header_block = payload.split(b'\r\n\r\n', 1)[0]
            for line in header_block.split(b'\r\n'):
                if b':' in line:
                    key, value = line.split(b':', 1)
                    headers[key.strip().decode('ascii', 'ignore')] = value.strip().decode('ascii', 'ignore')
        except Exception:
            pass
        return headers

    def _calculate_entropy(self, payload: bytes) -> float:
        """Calculate payload entropy for encrypted traffic detection"""
        if not payload:
            return 0.0
        counts = Counter(payload)
        probs = [c / len(payload) for c in counts.values()]
        return round(-sum(p * math.log2(p) for p in probs), 6)

    def _find_hex_patterns(self, payload: bytes) -> dict:
        """Identify suspicious hex patterns"""
        return {
            "magic_bytes": payload[:4].hex() if len(payload) >= 4 else None,
            "repeated_hex": bool(re.search(rb"(\x00{4,}|\xCC{4,})", payload)),
            "non_printable_ratio": (
                sum(c < 32 or c >= 127 for c in payload) / len(payload)
                if payload
                else 0
            ),
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

        # Regex normalization rules
        HEADER_NORMALIZATION_RULES = [
            (r"(?i)^(X-)?", ""),  # Remove X- prefixes for common headers
            (r"[^a-zA-Z0-9-]", ""),  # Remove special characters
            (r"\s+", " "),  # Collapse whitespace
        ]

        VALUE_NORMALIZATION_RULES = [
            (r"\s+", " "),  # Collapse whitespace
            (r"^ *(.*?) *$", r"\1"),  # Trim whitespace
            (r";.*", ""),  # Remove parameter comments
            (r"(?i)\\x[0-9a-f]{2}", "?"),  # Replace hex escapes
            (r"(?i)%[0-9a-f]{2}", "?"),  # Replace URL encoding
            (r"(?i)(true|false)", lambda m: m.group().title()),  # Normalize booleans
        ]

        def normalize_header(header: str) -> str:
            """Normalize header name with regex rules"""
            normalized = header.strip()
            for pattern, repl in HEADER_NORMALIZATION_RULES:
                normalized = re.sub(pattern, repl, normalized)
            return normalized.title()  # Convert to Title-Case

        def normalize_value(value: str) -> str:
            """Normalize header value with regex rules"""
            if not isinstance(value, str):
                return str(value)
            normalized = value.strip()
            for pattern, repl in VALUE_NORMALIZATION_RULES:
                normalized = re.sub(pattern, repl, normalized)
            return normalized

        normalized_headers = {}
        original_headers = {}

        # First pass: Normalize and collect headers
        for header, value in headers.items():
            # Preserve original values
            orig_header = header
            orig_value = value

            # Normalize versions
            norm_header = normalize_header(str(header))
            norm_value = normalize_value(str(value))

            # Store for comparison
            original_headers[orig_header] = orig_value
            normalized_headers[norm_header] = norm_value

            # Original injection checks (preserved)
            if isinstance(orig_value, str):
                if any(c in orig_value for c in ["\r", "\n", "\0"]):
                    tampering_indicators["header_injection"] = True

                # Original obfuscation check
                if any(ord(c) > 127 for c in orig_value):
                    tampering_indicators["obfuscated_headers"] = True

                # Original casing check
                if orig_header != orig_header.title():
                    tampering_indicators["unusual_casing"] = True

                # Original malformed value check
                if ";" in orig_value and "=" not in orig_value:
                    tampering_indicators["malformed_values"] = True

            # Additional checks using normalized values
            if any(c in norm_value for c in ["\r", "\n", "\0"]):
                tampering_indicators["header_injection"] = True

            if norm_header != header.title():
                tampering_indicators["unusual_casing"] = True

            if ";" in norm_value and "=" not in norm_value:
                tampering_indicators["malformed_values"] = True

        # Duplicate header check using normalized names
        unique_headers = set(normalized_headers.keys())
        if len(normalized_headers) != len(unique_headers):
            tampering_indicators["duplicate_headers"] = True

        # Special checks using normalized values
        for norm_header, norm_value in normalized_headers.items():
            if norm_header == "Content-Length":
                if not norm_value.isdigit() or int(norm_value) < 0:
                    tampering_indicators["invalid_format"] = True

            elif norm_header == "Host":
                if ":" in norm_value:
                    port_part = norm_value.split(":")[-1].split("]")[-1]  # Handle IPv6
                    if not port_part.isdigit():
                        tampering_indicators["invalid_format"] = True

            elif norm_header == "User-Agent":
                if re.search(r"(?:[^\w\-\.]|^)\d{10,}(?:[^\w\-\.]|$)", norm_value):
                    tampering_indicators["malformed_values"] = True

        return tampering_indicators

    def _safe_extract(self, layer: Packet, attribute: str) -> Optional[str]:
        """
        Safely extract attributes from HTTP layers with comprehensive error handling
        """
        try:
            # Direct field access
            if hasattr(layer, attribute):
                value = getattr(layer, attribute)
            # Try lower-case fallback
            elif hasattr(layer, attribute.lower()):
                value = getattr(layer, attribute.lower())
            # Try fields dict
            elif attribute in layer.fields:
                value = layer.fields[attribute]
            else:
                return None

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
            logger.warning("Chunked decode failed: %s", str(e))
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
            logger.warning("GZIP decompress failed: %s", str(e))
            return payload

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
        try:
            logger.info("Analysis of DNS started")
            if not (packet.haslayer(DNS) and packet.haslayer(IP)):
                return

            dns = packet[DNS]
            ip = packet[IP]
            
            queries = []
            responses = []

            # Query processing
            if dns.qr == 0 and dns.qd:  # Query
                queries.append({
                    "name": dns.qd.qname.decode(errors="replace").strip('.') if dns.qd.qname else "",
                    "type": int(dns.qd.qtype),
                })

            # Response processing
            elif dns.qr == 1 and dns.an:  # Response
                for answer in dns.an:
                    responses.append({
                        "name": answer.rrname.decode(errors="replace").strip('.') if answer.rrname else "",
                        "type": int(answer.type),
                        "ttl": int(answer.ttl),
                        "data": str(answer.rdata) if hasattr(answer, "rdata") else None,
                    })

            # Data collection with type safety
            dns_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "source_ip": ip.src,
                "queries": queries,
                "responses": responses,
                "is_suspicious": any(q.get("type", 0) in {12, 16} for q in queries),
                "tunnel_analysis": {
                    "likely_tunnel": bool(self._detect_dns_tunneling(queries, responses)),
                    "dga_score": float(self._calculate_dga_score(queries)),
                },
                "correlation_features": {
                    "query_chain_depth": len([rr for rr in responses if rr.get("type") == 5]),
                    "nxdomain_ratio": float(self._get_nxdomain_ratio(queries)),
                    "ttl_variation": float(np.std([r["ttl"] for r in responses])) if responses else 0.0,
                    "subdomain_entropy": float(self._calculate_subdomain_entropy(queries)),
                },
                "nxdomain_ratio": float(self._get_nxdomain_ratio(queries)),
                "unique_domains": int(len({q["name"] for q in queries if q.get("name")})),
            }

            # Add TTL analysis safely
            if responses:
                avg_ttl = sum(r["ttl"] for r in responses) / len(responses)
                dns_data["ttl_anomaly"] = bool(avg_ttl < 30)

            try:
                self.sio_queue.put_nowait(("dns_activity", dns_data))
                logger.info("Analysis of DNS ended")
            except Full:
                logger.warning("DNS queue full, dropping packet")

        except Exception as e:
            logger.error(f"DNS analysis failed: {str(e)}", exc_info=True)
            self.sio_queue.put(('system_error', {
                'error': 'dns_analysis_failed',
                'message': str(e),
                'packet_summary': packet.summary() if 'packet' in locals() else None
            }))

    def _calculate_subdomain_entropy(self, queries: list) -> float:
        """Calculate entropy of subdomain labels"""
        labels = [q["name"].split(".")[-2] for q in queries if "." in q["name"]]
        counter = Counter(labels)
        probs = [c / len(labels) for c in counter.values()]
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
                    with self.data_lock:
                        self.stats["threat_types"]["ssh_bruteforce"] += 1
            except UnicodeDecodeError:
                ssh_data["is_encrypted"] = True

        self.sio_queue.put(("ssh_activity", ssh_data))
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
        with self.data_lock:
            self.stats["alerts"].append(alert)
            self.stats["threat_types"][alert_type] += 1

        # Emit via Socket.IO

        self.sio_queue.put(( "security_alert", alert))

        # Log to database
        self._log_threat_to_db(alert)

    def _log_threat_to_db(self, alert: Dict):
        """Log threat to database"""
        try:
            db = get_db()
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
            logger.error("Failed to log threat: %s", str(e))
            self.sio_queue.put(( "database_error", {
                        "operation": "threat_logging",
                        "error": str(e),
                        "timestamp": datetime.utcnow().isoformat(),
                    }))

    def _log_packet_to_db(self, packet_data: dict):
        """Enhanced packet logging with safe model validation"""
        try:
            valid_fields = self.get_model_fields(Packets)
            filtered_data = {k: v for k, v in packet_data.items() if k in valid_fields}

            if not filtered_data:
                logger.warning("No valid fields found for packet")
                return

            db = next(get_db())
            packet = Packets(**filtered_data)
            db.add(packet)
            db.commit()

        except Exception as e:
            logger.error("Logging failed: %s", str(e))

    # def start(self, interface: str = "Wi-Fi"):
    #     """Start sniffing with enhanced error handling"""
    #     if (
    #         getattr(self, "sniffer_process", None) is not None
    #         and self.sniffer_process.is_alive()
    #     ):
    #         logger.warning("Sniffer already running")

    #         return

    #     # Initialize interface
    #     interface = interface or conf.iface

    #     if not interface:
    #         interface = conf.iface
    #     self.worker_process = Process(target=self._process_queue, daemon=True)
    #     self.sniffer_process = Process(
    #         target=self._start_sniffing,
    #         args=(interface,),
    #         daemon=True,
    #     )
    #     self.stop_event.clear()
    #     self.worker_process.start()
    #     self.sniffer_process.start()
    #     self.reporter_process.start()

    #     logger.info("Started packet sniffing on interface %s" , interface)

    #     # Send system alert
    #     self.sio_queue.put(
    #         (
    #             "system_status",
    #             {
    #                 "component": "packet_sniffer",
    #                 "status": "running",
    #                 "interface": interface,
    #                 "timestamp": datetime.utcnow().isoformat(),
    #             },
    #         )
    #     )

    def start(self, interface: str = None):
        """Start both the queue‑processor and the packet capture thread."""
        interface = interface or conf.iface
        if not interface:
            raise RuntimeError("No interface specified")

        # 1) start your queue‑processor
        if not self.worker_process or not self.worker_process.is_alive():
            self.worker_process = Process(target=self._process_queue, daemon=True)
            self.worker_process.start()

        # 2) start the AsyncSniffer
        if self._async_sniffer and self._async_sniffer.running:
            logger.warning("Sniffer already running")
        else:
            self._async_sniffer = AsyncSniffer(
                iface=interface,
                filter="not (dst net 127.0.0.1 or multicast or ip6)",
                prn=self._packet_handler,
                store=False,
            )
            self._async_sniffer.start()
            logger.info("AsyncSniffer started on %s", interface)

        # 3) start reporter
        if not self.reporter_process or not self.reporter_process.is_alive():
            self.reporter_process = Process(
            target=_reporter_loop,
            args=(self.sio_queue, self.stats, self._reporter_stop,5.0),
            daemon=True,
        )
            self.reporter_process.start()

        # 4) send system status
        self.sio_queue.put((
            "system_status",
            {
                "component": "packet_sniffer",
                "status": "running",
                "interface": interface,
                "timestamp": datetime.utcnow().isoformat(),
            }
        ))

    # def _start_sniffing(self, interface: str):
    #     """Internal sniffing method with proper resource cleanup"""
    #     try:
    #         # Explicitly create new socket in the process
    #         with conf.L2listen(
    #             iface=interface,
    #             filter="not (dst net 127.0.0.1 or multicast or ip6)"
    #         ) as sock:
    #             sniff(
    #                 opened_socket=sock,
    #                 prn=self._packet_handler,
    #                 stop_filter=lambda _: self.stop_event.is_set(),
    #                 store=False,

    #             )
    #     except Exception as e:
    #         logger.error(f"Sniffing error: {str(e)}")
    #         self.sio_queue.put(("system_error", {
    #             "component": "packet_capture",
    #             "error": str(e),
    #             "timestamp": datetime.utcnow().isoformat(),
    #         }))

    def _start_sniffing(self, interface: str):
        """Capture packets forever (until process is killed)"""
        try:
            with conf.L2listen(
                iface=interface,
                filter="not (dst net 127.0.0.1 or multicast or ip6)"
            ) as sock:
                sniff(
                    opened_socket=sock,
                    prn=self._packet_handler,
                    store=False
                    # no stop_filter, no count → infinite
                )
        except Exception as e:
            logger.error(f"Sniffing error: {e}")
            self.sio_queue.put(("system_error", {
                "component": "packet_capture",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }))

    # def stop(self):
    #     """Graceful shutdown with comprehensive cleanup and monitoring"""
    #     self._running = False
    #     if hasattr(self, "manager"):
    #         self.manager.shutdown()
    #     if not self.stop_event.is_set():
    #         self.stop_event.set()

    #         # Send pre-shutdown notification

    #         self.sio_queue.put(
    #             (
    #                 "system_status",
    #                 {
    #                     "component": "packet_sniffer",
    #                     "status": "stopping",
    #                     "timestamp": datetime.utcnow().isoformat(),
    #                 },
    #             )
    #         )

    #     packet_count = self.packet_counter.value
    #     uptime = time.time() - self.start_time

    #     # Terminate processes with timeout
    #     processes = [
    #         self.sniffer_process,
    #         self.worker_process,
    #         self.reporter_process
    #     ]

    #     for p in processes:
    #         if p and p.is_alive():
    #             p.terminate()  # Forceful termination if needed
    #             p.join(timeout=2)
    #             if p.exitcode is None:
    #                 logger.warning(f"{p.name} did not terminate gracefully")

    #     # Final status update with safe values
    #     logger.info(
    #         "Packet sniffer stopped. Processed %d packets. Uptime: %.2f seconds",
    #         packet_count,
    #         uptime
    #     )

    def stop(self):
        """Stop packet capture and cleanup."""
        # stop the AsyncSniffer
        if self._async_sniffer:
            self._async_sniffer.stop()
            logger.info("AsyncSniffer stopped")
            
            # self.recorder.flush_remaining_on_exit()

        # stop worker and reporter as you already have
        if self.worker_process:
            self.worker_process.terminate()
        if self.reporter_process and self.reporter_process.is_alive():
            self._reporter_stop.set()
            self.reporter_process.terminate()
            self.reporter_process = None
            self.end_time = time.perf_counter()
            
            logger.info("processed %d packets in %d secons", self.packet_counter.value, (self.end_time - self.start_time))
        # send stopping status
        self.sio_queue.put((
            "system_status",
            {
                "component": "packet_sniffer",
                "status": "stopped",
                "timestamp": datetime.utcnow().isoformat(),
            }
        ))

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
        with self.data_lock:
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

    @staticmethod
    def get_model_fields(model):
        """Safely get column names from SQLAlchemy model"""
        try:
            return [c.key for c in inspect(model).mapper.column_attrs]
        except Exception as e:
            logger.error("Model inspection failed: %s", str(e))
            return []
