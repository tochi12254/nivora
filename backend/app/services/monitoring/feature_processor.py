import time
import hashlib
import numpy as np
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
import logging
from dataclasses import dataclass, field
import statistics
from collections import OrderedDict
import csv
import json
import os
import traceback
import threading
from multiprocessing import Queue
import multiprocessing
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
    wrpcap,
)
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet6 import IPv6ExtHdrFragment
from scapy.packet import Packet
from statistics import mean, stdev

logger = logging.getLogger(__name__)


def new_deque():
    return deque()


def default_int():
    return defaultdict(int)


@dataclass
class FlowKey:
    """Unique identifier for network flows"""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

    def __hash__(self):
        return hash(
            (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.protocol)
        )


@dataclass
class PacketMetrics:
    """Individual packet metrics"""

    size: int
    payload_size: int
    pkt: Packet
    header_size: int
    timestamp: float = field(default_factory=time.time)
    flags: str = ""
    tcp_window_size: int = 0
    tcp_urgent_ptr: int = 0
    tcp_options_len: int = 0
    ip_ttl: int = 0
    ip_flags: int = 0
    ip_fragment_offset: int = 0
    icmp_type: int = -1
    icmp_code: int = -1


@dataclass
class FlowStatistics:
    """Comprehensive flow statistics"""

    # Basic flow info
    start_time: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    duration: float = 0.0
    unique_dest_ips: Set[str] = field(default_factory=set)
    protocols_seen: Set[int] = field(default_factory=set)
    last_forward_time: Optional[float] = None
    last_backward_time: Optional[float] = None
    # Packet counts
    total_packets: int = 0
    forward_packets: int = 0
    backward_packets: int = 0

    # Size statistics
    total_length_forward: int = 0
    total_length_backward: int = 0
    forward_packet_lengths: List[int] = field(default_factory=list)
    backward_packet_lengths: List[int] = field(default_factory=list)

    # Header lengths
    forward_header_lengths: List[int] = field(default_factory=list)
    backward_header_lengths: List[int] = field(default_factory=list)
    backward_psh_flags: int = 0
    backward_urg_flags: int = 0
    act_data_pkt_fwd: int = 0
    min_seg_size_forward: int = 0
    init_win_forward: Optional[int] = None
    init_win_backward: Optional[int] = None

    # Timing statistics
    forward_iat: List[float] = field(default_factory=list)  # Inter-arrival times
    backward_iat: List[float] = field(default_factory=list)
    flow_iat: List[float] = field(default_factory=list)

    # TCP-specific
    tcp_flags_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    syn_flag_count: int = 0
    cwe_flag_count: int = 0  # CWR, ECE, URG flags
    tcp_window_size: int = 0
    tcp_urgent_pointer: int = 0
    tcp_sequence_number: int = 0
    tcp_acknowledgment_number: int = 0
    tcp_reserved_bits: int = 0
    tcp_checksum: int = 0
    tcp_options_count: int = 0
    packets: List[Any] = field(default_factory=list)  # List[scapy.Packet]
    # Active/Idle time tracking
    active_times: List[float] = field(default_factory=list)
    idle_times: List[float] = field(default_factory=list)
    last_activity: float = field(default_factory=time.time)

    # Advanced metrics
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0

    # Bulk transfer characteristics
    bulk_duration_forward: float = 0.0
    bulk_duration_backward: float = 0.0
    bulk_packet_count_forward: int = 0
    bulk_packet_count_backward: int = 0
    bulk_size_avg_forward: float = 0.0
    bulk_size_avg_backward: float = 0.0

    # Subflow characteristics
    subflow_forward_packets: int = 0
    subflow_forward_bytes: int = 0
    subflow_backward_packets: int = 0
    subflow_backward_bytes: int = 0
    forward_payload_lengths: List[int] = field(default_factory=list)
    backward_payload_lengths: List[int] = field(default_factory=list)
    last_flow_time: Optional[float] = None


class AdvancedFeatureExtractor:
    """Advanced feature extraction for network packets aligned with CICIDS datasets"""

    def __init__(self, cleanup_interval: int = 300, flow_timeout: int = 120):
        self.flows: Dict[FlowKey, FlowStatistics] = {}
        self.flow_packets: Dict[FlowKey, List[PacketMetrics]] = {}
        self.cleanup_interval = cleanup_interval
        self.flow_timeout = flow_timeout
        self.host_windows = defaultdict(new_deque)
        self.last_cleanup = time.time()

        self.lock = multiprocessing.Lock()

        # Behavioral tracking
        self.ip_behavior = defaultdict(self.default_ip_behavior)
        # Protocol detection patterns
        self.protocol_signatures = {
            "HTTP": [80, 8080, 8000, 3128],
            "HTTPS": [443, 8443, 9443],
            "FTP": [21, 20],
            "SSH": [22],
            "TELNET": [23],
            "SMTP": [25, 587, 465],
            "DNS": [53],
            "DHCP": [67, 68],
            "POP3": [110, 995],
            "IMAP": [143, 993],
            "SNMP": [161, 162],
            "LDAP": [389, 636],
            "SMB": [445, 139],
            "RDP": [3389],
            "VNC": [5900, 5901, 5902],
        }

    def compute_features(self, flow_key, pkt_count: int) -> Dict[str, Any]:
        st = self.flows[flow_key]
        f = {}

        f["Flow_Duration"] = st.duration * 1e6  # Convert to microseconds
        f["Total_Fwd_Packets"] = st.forward_packets
        f["Total_Backward_Packets"] = st.backward_packets
        f["Total_Length_of_Fwd_Packets"] = st.total_length_forward
        f["Total_Length_of_Bwd_Packets"] = st.total_length_backward

        def safe_stats(data, use_percentiles=True):
            """Safe statistics calculation with non-negative enforcement"""
            clean_data = [x for x in data if x >= 0]  # Filter negatives
            if not clean_data:
                result = {"min": 0, "max": 0, "mean": 0, "std": 0}
                if use_percentiles:
                    result.update({"p25": 0, "p50": 0, "p75": 0})
                return result

            result = {
                "min": min(clean_data),
                "max": max(clean_data),
                "mean": mean(clean_data),
                "std": stdev(clean_data) if len(clean_data) > 1 else 0,
            }

            if use_percentiles:
                result["p25"] = np.percentile(clean_data, 25) if clean_data else 0
                result["p50"] = np.percentile(clean_data, 50) if clean_data else 0
                result["p75"] = np.percentile(clean_data, 75) if clean_data else 0

            return result

        fwd_stats = safe_stats(st.forward_packet_lengths)
        bwd_stats = safe_stats(st.backward_packet_lengths)

        for name, stats in [("Fwd", fwd_stats), ("Bwd", bwd_stats)]:
            for suffix, val in stats.items():
                suffix_map = {"p25": "25th", "p50": "50th", "p75": "75th"}
                key_suffix = suffix_map.get(suffix, suffix.capitalize())
                f[f"{name}_Packet_Length_{key_suffix}"] = val

        for direction, iats in [
            ("Flow", st.flow_iat),
            ("Fwd", st.forward_iat),
            ("Bwd", st.backward_iat),
        ]:
            if iats:
                f[f"{direction}_IAT_Total"] = sum(iats) if direction != "Flow" else None
                f[f"{direction}_IAT_Mean"] = mean(iats)
                f[f"{direction}_IAT_Std"] = stdev(iats) if len(iats) > 1 else 0
                f[f"{direction}_IAT_Max"] = max(iats)
                f[f"{direction}_IAT_Min"] = min(iats)
            else:
                for suffix in ["Total", "Mean", "Std", "Max", "Min"]:
                    if direction != "Flow" or suffix != "Total":
                        f[f"{direction}_IAT_{suffix}"] = 0

        for flag in ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWE", "ECE"]:
            f[f"{flag}_Flag_Count"] = st.tcp_flags_counts.get(flag, 0)

        if st.forward_header_lengths:
            f["Fwd_Header_Length"] = mean(st.forward_header_lengths)
        else:
            f["Fwd_Header_Length"] = 0.0

        if st.backward_header_lengths:
            f["Bwd_Header_Length"] = mean(st.backward_header_lengths)
        else:
            f["Bwd_Header_Length"] = 0.0

        dur = f["Flow_Duration"] / 1e6 if f["Flow_Duration"] > 0 else 1
        total_bytes = st.total_length_forward + st.total_length_backward
        total_pkts = st.forward_packets + st.backward_packets

        f["Flow_Bytes_s"] = total_bytes / dur
        f["Flow_Packets_s"] = total_pkts / dur
        f["Fwd_Packets_s"] = st.forward_packets / dur
        f["Bwd_Packets_s"] = st.backward_packets / dur
        f["Down_Up_Ratio"] = (
            st.backward_packets / st.forward_packets if st.forward_packets > 0 else 0
        )
        f["Average_Packet_Size"] = total_bytes / total_pkts if total_pkts > 0 else 0
        f["Avg_Fwd_Segment_Size"] = (
            mean(st.forward_packet_lengths) if st.forward_packet_lengths else 0
        )
        f["Avg_Bwd_Segment_Size"] = (
            mean(st.backward_packet_lengths) if st.backward_packet_lengths else 0
        )

        if len(st.active_times) >= 2:
            f["Active_Mean"] = mean(st.active_times)
            f["Active_Std"] = stdev(st.active_times)
            f["Active_Max"] = max(st.active_times)
            f["Active_Min"] = min(st.active_times)
        else:
            for k in ["Mean", "Std", "Max", "Min"]:
                f[f"Active_{k}"] = 0

        f["Subflow_Fwd_Packets"] = st.subflow_forward_packets or st.forward_packets
        f["Subflow_Fwd_Bytes"] = st.subflow_forward_bytes or st.total_length_forward
        f["Subflow_Bwd_Packets"] = st.subflow_backward_packets or st.backward_packets
        f["Subflow_Bwd_Bytes"] = st.subflow_backward_bytes or st.total_length_backward

        now = time.time()
        flow_stats = self.flows[flow_key]
        hwin = self.host_windows[flow_key.src_ip]
        while hwin and now - hwin[0][0] > 60:
            hwin.popleft()

        dst_ports = {pkt[TCP].dport for pkt in st.packets if TCP in pkt}
        f["port_scan_score"] = len(dst_ports)
        f["connection_rate"] = len({(d, p) for _, _, d, p in hwin})
        f["host_flows_60s"] = len(
            {
                k
                for k, v in self.flows.items()
                if k.src_ip == flow_key.src_ip and (now - v.last_seen) <= 60
            }
        )
        f["host_bytes_60s"] = sum(size for _, size, _, _ in hwin)

        f["tcp_window_size"] = st.tcp_window_size
        f["tcp_urgent_pointer"] = st.tcp_urgent_pointer
        f["tcp_sequence_number"] = st.tcp_sequence_number
        f["tcp_acknowledgment_number"] = st.tcp_acknowledgment_number
        f["tcp_reserved_bits"] = st.tcp_reserved_bits
        f["tcp_checksum"] = st.tcp_checksum
        f["tcp_options_count"] = st.tcp_options_count

        f["unique_destinations_count"] = len(st.unique_dest_ips)
        f["protocols_count"] = len(st.protocols_seen)
        f["requests_per_minute"] = f["connection_rate"]
        f["Init_Win_bytes_forward"] = flow_stats.init_win_forward or 0
        f["Init_Win_bytes_backward"] = flow_stats.init_win_backward or 0

        f["Label"] = "BENIGN"
        return f

    def update_flow(self, packet: Packet) -> Optional[FlowStatistics]:
        packet_info = self._extract_basic_info(packet)
        if not packet_info:
            return None

        flow_key = self._create_flow_key(packet_info)
        if not flow_key:
            return None

        now = packet_info["timestamp"]  # Current packet's timestamp

        if flow_key not in self.flows:
            self.flows[flow_key] = FlowStatistics(
                start_time=now, last_seen=now, last_activity=now
            )
            self.flow_packets[flow_key] = []
            st = self.flows[flow_key]
        else:
            st = self.flows[flow_key]
            st.start_time = min(st.start_time, now)
            st.last_seen = max(st.last_seen, now)
            # last_activity will be updated later

        # Update duration
        st.duration = max(0, st.last_seen - st.start_time)

        # Store packet
        st.packets.append(packet)
        self.flow_packets[flow_key].append(packet)

        # Update direction
        direction = packet_info.get("direction", "forward")
        length = packet_info.get("length", 0)
        header_len = packet_info.get("header_length", 0)

        st.total_packets += 1
        if direction == "forward":
            st.forward_packets += 1
            st.total_length_forward += length
            st.forward_packet_lengths.append(length)
            st.forward_header_lengths.append(header_len)
            st.act_data_pkt_fwd += 1
        else:
            st.backward_packets += 1
            st.total_length_backward += length
            st.backward_packet_lengths.append(length)
            st.backward_header_lengths.append(header_len)

        # Update IATs
        if st.last_activity:
            iat = now - st.last_activity
            st.flow_iat.append(iat)
            if direction == "forward":
                st.forward_iat.append(iat)
            else:
                st.backward_iat.append(iat)

        st.last_activity = now

        # Unique destination IPs and protocol tracking
        ip = packet[IP]
        st.unique_dest_ips.add(ip.dst)
        st.protocols_seen.add(ip.proto)

        # TCP-specific
        if TCP in packet:
            tcp = packet[TCP]
            if direction == "backward":
                if tcp.flags & 0x08:  # PSH
                    st.backward_psh_flags += 1
                if tcp.flags & 0x20:  # URG
                    st.backward_urg_flags += 1

            flags = {
                "FIN": 0x01,
                "SYN": 0x02,
                "RST": 0x04,
                "PSH": 0x08,
                "ACK": 0x10,
                "URG": 0x20,
                "ECE": 0x40,
                "CWE": 0x80,
            }
            for name, bit in flags.items():
                if tcp.flags & bit:
                    st.tcp_flags_counts[name] += 1

            # Record TCP fields
            st.tcp_window_size = tcp.window
            st.tcp_urgent_pointer = tcp.urgptr
            st.tcp_sequence_number = tcp.seq
            st.tcp_acknowledgment_number = tcp.ack
            st.tcp_reserved_bits = tcp.reserved
            st.tcp_checksum = tcp.chksum
            st.tcp_options_count = len(tcp.options) if tcp.options else 0

        # Update sliding window (host_bytes_60s, connection_rate)
        src_ip = ip.src
        self.host_windows[src_ip].append(
            (now, length, ip.dst, tcp.dport if TCP in packet else 0)
        )

        return st

    def clear_flow(self, fk: FlowKey):
        """
        Cleanly remove the state associated with a completed or expired flow.
        Called after detecting flow termination (e.g., TCP FIN or RST).
        """
        flow_exists = fk in self.flows

        if flow_exists:
            del self.flows[fk]

            # Log flow cleanup (for debugging or audit purposes)
            print(
                f"[INFO] Cleared flow: {fk.src_ip}:{fk.src_port} → {fk.dst_ip}:{fk.dst_port} (Protocol {fk.protocol})"
            )

        else:
            # Log unexpected cleanup attempt
            print(
                f"[WARNING] Attempted to clear unknown flow: {fk.src_ip}:{fk.src_port} → {fk.dst_ip}:{fk.dst_port} (Protocol {fk.protocol})"
            )

    def _cleanup_old_flows(self, timeout: float = 60.0):
        now = time.time()
        expired = [fk for fk, fs in self.flows.items() if now - fs.last_seen > timeout]
        for fk in expired:
            pkt_count = self.flows[fk].total_packets
            features = self.compute_features(fk, pkt_count)
            if features:
                self._append_features_row("ml_ready_features.csv", features)
            del self.flows[fk]
            if fk in self.flow_packets:
                del self.flow_packets[fk]

    def flow_key(self, packet):
        # build your 5‐tuple key object
        return FlowKey(
            src_ip=packet[IP].src,
            dst_ip=packet[IP].dst,
            src_port=packet[TCP].sport,
            dst_port=packet[TCP].dport,
            protocol=6,
        )

    def default_ip_behavior(self):
        """Default behavior tracking for new IPs"""
        return {
            "port_scan_attempts": set(),
            "connection_attempts": 0,
            "failed_connections": 0,
            "unique_destinations": set(),
            "protocols_used": set(),
            "first_seen": time.time(),
            "packet_sizes": [],
            "request_rates": deque(maxlen=100),
        }

    def extract_features(self, packet: Packet) -> Dict[str, Any]:
        """Main feature extraction method"""
        try:
            with self.lock:
                # Cleanup old flows periodically
                if time.time() - self.last_cleanup > self.cleanup_interval:
                    self._cleanup_old_flows()

                # Extract basic packet information
                packet_info = self._extract_basic_info(packet)
                if not packet_info:
                    return {}

                # Create flow key
                flow_key = self._create_flow_key(packet_info)
                if not flow_key:
                    return {}

                # Get or create flow statistics
                now = packet.time  # Current packet's timestamp

                if flow_key not in self.flows:
                    self.flows[flow_key] = FlowStatistics(
                        start_time=now, last_seen=now, last_activity=now
                    )
                    self.flow_packets[flow_key] = []
                    flow_stats = self.flows[flow_key]
                else:
                    flow_stats = self.flows[flow_key]
                    # Ensure start_time is the minimum and last_seen is the maximum
                    flow_stats.start_time = min(flow_stats.start_time, now)
                    flow_stats.last_seen = max(flow_stats.last_seen, now)

                # Update duration consistently
                flow_stats.duration = max(
                    0, flow_stats.last_seen - flow_stats.start_time
                )

                # Append packet
                self.flow_packets[flow_key].append(packet)
                flow_stats.packets.append(packet)

                # Directional handling
                direction = packet_info.get("direction", "forward")
                length = packet_info.get("length", 0)
                header_len = packet_info.get("header_length", 0)

                flow_stats.total_packets += 1
                # flow_stats.duration = now - flow_stats.start_time # This was the old line
                # flow_stats.last_seen = now # This is already set prior to duration calculation

                if direction == "forward":
                    flow_stats.forward_packets += 1
                    flow_stats.total_length_forward += length
                    flow_stats.forward_packet_lengths.append(length)
                    flow_stats.forward_header_lengths.append(header_len)
                    flow_stats.act_data_pkt_fwd += 1
                else:
                    flow_stats.backward_packets += 1
                    flow_stats.total_length_backward += length
                    flow_stats.backward_packet_lengths.append(length)
                    flow_stats.backward_header_lengths.append(header_len)

                # IAT tracking
                if flow_stats.last_activity:
                    iat = now - flow_stats.last_activity
                    flow_stats.flow_iat.append(iat)
                    if direction == "forward":
                        flow_stats.forward_iat.append(iat)
                    else:
                        flow_stats.backward_iat.append(iat)
                flow_stats.last_activity = now

                # Unique destination tracking
                ip = packet[IP]
                flow_stats.unique_dest_ips.add(ip.dst)
                flow_stats.protocols_seen.add(ip.proto)

                # TCP field tracking
                if TCP in packet:
                    tcp = packet[TCP]
                    if direction == "backward":
                        if tcp.flags & 0x08:
                            flow_stats.backward_psh_flags += 1
                        if tcp.flags & 0x20:
                            flow_stats.backward_urg_flags += 1

                    flags = {
                        "FIN": 0x01,
                        "SYN": 0x02,
                        "RST": 0x04,
                        "PSH": 0x08,
                        "ACK": 0x10,
                        "URG": 0x20,
                        "ECE": 0x40,
                        "CWE": 0x80,
                    }
                    for name, bit in flags.items():
                        if tcp.flags & bit:
                            flow_stats.tcp_flags_counts[name] += 1

                    flow_stats.tcp_window_size = tcp.window
                    flow_stats.tcp_urgent_pointer = tcp.urgptr
                    flow_stats.tcp_sequence_number = tcp.seq
                    flow_stats.tcp_acknowledgment_number = tcp.ack
                    flow_stats.tcp_reserved_bits = tcp.reserved
                    flow_stats.tcp_checksum = tcp.chksum
                    flow_stats.tcp_options_count = (
                        len(tcp.options) if tcp.options else 0
                    )

                # Add to host-based sliding window
                self.host_windows[ip.src].append(
                    (now, length, ip.dst, tcp.dport if TCP in packet else 0)
                )

                # === Existing logic preserved ===
                packet_metrics = self._create_packet_metrics(packet, packet_info)
                self._update_flow_statistics(flow_key, packet_metrics, packet_info)

                features = self._compute_flow_features(flow_key, packet_info)

                behavioral_features = self._extract_behavioral_features(packet_info)
                features.update(behavioral_features)

                protocol_features = self._extract_protocol_features(packet, packet_info)
                features.update(protocol_features)

                return features

        except Exception as e:
            # Capture the full traceback—including the chain of causes—and log it
            tb = traceback.format_exc()
            logger.error(
                "Feature extraction error: %s\nFull traceback:\n%s",
                e,
                tb
            )
            # Optionally, if you want to see __cause__ / __context__ explicitly:
            if e.__cause__:
                logger.error("Underlying cause: %s", repr(e.__cause__))
            elif e.__context__:
                logger.error("Context exception: %s", repr(e.__context__))
            return {}

    def _extract_basic_info(self, packet: Packet) -> Optional[Dict]:
        """Extract basic packet information"""
        timestamp = packet.time if hasattr(packet, "time") else time.time()
        try:
            info = {
                "timestamp": timestamp,
                "size": len(packet),
                "src_ip": None,
                "dst_ip": None,
                "src_port": 0,
                "dst_port": 0,
                "protocol": "Other",
                "ip_version": None,
            }

            # Layer 3 (Network Layer)
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                info.update(
                    {
                        "src_ip": ip_layer.src,
                        "dst_ip": ip_layer.dst,
                        "ip_version": 4,
                        "ip_ttl": ip_layer.ttl,
                        "ip_flags": ip_layer.flags,
                        "ip_fragment_offset": ip_layer.frag,
                        "ip_header_len": ip_layer.ihl * 4,
                        "ip_tos": ip_layer.tos,
                        "ip_id": ip_layer.id,
                    }
                )
            elif packet.haslayer(IPv6):
                ipv6_layer = packet[IPv6]
                info.update(
                    {
                        "src_ip": ipv6_layer.src,
                        "dst_ip": ipv6_layer.dst,
                        "ip_version": 6,
                        "ip_ttl": ipv6_layer.hlim,
                        "ip_flow_label": ipv6_layer.fl,
                    }
                )
            elif packet.haslayer(ARP):
                arp_layer = packet[ARP]
                info.update(
                    {
                        "src_ip": arp_layer.psrc,
                        "dst_ip": arp_layer.pdst,
                        "protocol": "ARP",
                    }
                )
                return info
            else:
                return None

            # Layer 4 (Transport Layer)
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                info.update(
                    {
                        "src_port": tcp_layer.sport,
                        "dst_port": tcp_layer.dport,
                        "protocol": "TCP",
                        "tcp_flags": tcp_layer.flags,
                        "tcp_window_size": tcp_layer.window,
                        "tcp_urgent_ptr": tcp_layer.urgptr,
                        "tcp_seq": tcp_layer.seq,
                        "tcp_ack": tcp_layer.ack,
                        "tcp_header_len": tcp_layer.dataofs * 4,
                    }
                )

                # TCP options
                if tcp_layer.options:
                    info["tcp_options_len"] = sum(
                        len(opt) if isinstance(opt, tuple) else 1
                        for opt in tcp_layer.options
                    )

            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                info.update(
                    {
                        "src_port": udp_layer.sport,
                        "dst_port": udp_layer.dport,
                        "protocol": "UDP",
                        "udp_length": udp_layer.len,
                    }
                )

            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                info.update(
                    {
                        "protocol": "ICMP",
                        "icmp_type": icmp_layer.type,
                        "icmp_code": icmp_layer.code,
                    }
                )

            # Calculate payload size
            if packet.haslayer(Raw):
                info["payload_size"] = len(packet[Raw])
            else:
                info["payload_size"] = 0

            info["header_size"] = info["size"] - info["payload_size"]

            return info

        except Exception as e:
            logger.debug(f"Basic info extraction error: {e}")
            return None

    def _create_flow_key(self, packet_info: Dict) -> Optional[FlowKey]:
        """Create a flow key for packet categorization"""
        try:
            src_ip = packet_info.get("src_ip")
            dst_ip = packet_info.get("dst_ip")
            src_port = packet_info.get("src_port", 0)
            dst_port = packet_info.get("dst_port", 0)
            protocol = packet_info.get("protocol", "Other")

            if not src_ip or not dst_ip:
                return None

            # Normalize flow direction (smaller IP first for bidirectional flows)
            if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
                return FlowKey(src_ip, dst_ip, src_port, dst_port, protocol)
            else:
                return FlowKey(dst_ip, src_ip, dst_port, src_port, protocol)

        except Exception as e:
            logger.debug(f"Flow key creation error: {e}")
            return None

    def _create_packet_metrics(
        self, packet: Packet, packet_info: Dict
    ) -> PacketMetrics:
        """Create packet metrics object"""
        return PacketMetrics(
            timestamp=packet_info.get("timestamp", time.time()),
            size=packet_info["size"],
            pkt=packet,
            payload_size=packet_info.get("payload_size", 0),
            header_size=packet_info.get("header_size", 0),
            flags=str(packet_info.get("tcp_flags", "")),
            tcp_window_size=packet_info.get("tcp_window_size", 0),
            tcp_urgent_ptr=packet_info.get("tcp_urgent_ptr", 0),
            tcp_options_len=packet_info.get("tcp_options_len", 0),
            ip_ttl=packet_info.get("ip_ttl", 0),
            ip_flags=packet_info.get("ip_flags", 0),
            ip_fragment_offset=packet_info.get("ip_fragment_offset", 0),
            icmp_type=packet_info.get("icmp_type", -1),
            icmp_code=packet_info.get("icmp_code", -1),
        )

    def _update_flow_statistics(
        self, flow_key: FlowKey, packet_metrics: PacketMetrics, packet_info: Dict
    ):
        """Update flow statistics with new packet"""
        flow_stats = self.flows[flow_key]
        flow_packets = self.flow_packets[flow_key]
        pkt = packet_metrics.pkt

        current_time = (
            packet_metrics.timestamp if packet_metrics.timestamp else time.time()
        )

        # current_time is packet_metrics.timestamp

        if (
            flow_stats.total_packets == 0
        ):  # This implies it's the first packet metric being processed for this flow_stats object
            flow_stats.start_time = current_time
            flow_stats.last_forward_time = current_time
            flow_stats.last_backward_time = current_time
            flow_stats.last_flow_time = current_time
            flow_stats.last_activity = current_time
            flow_stats.last_seen = current_time
        else:
            # Ensure start_time is the minimum and last_seen is the maximum
            flow_stats.start_time = min(flow_stats.start_time, current_time)
            flow_stats.last_seen = max(flow_stats.last_seen, current_time)

        flow_stats.duration = max(0, flow_stats.last_seen - flow_stats.start_time)
        # flow_stats.total_packets will be incremented after this block, so increment it here.
        flow_stats.total_packets += 1

        # Determine flow direction
        is_forward = (
            packet_info["src_ip"] == flow_key.src_ip
            and packet_info["src_port"] == flow_key.src_port
        )

        if is_forward:
            if flow_stats.last_forward_time is not None:
                if current_time < flow_stats.last_forward_time:
                    logger.warning(
                        f"Timestamp anomaly: current_time ({current_time}) < last_forward_time ({flow_stats.last_forward_time}) for flow {flow_key}"
                    )
                iat_forward = max(0, current_time - flow_stats.last_forward_time)
                flow_stats.forward_iat.append(iat_forward)
            flow_stats.last_forward_time = current_time
        else:
            if flow_stats.last_backward_time is not None:
                if current_time < flow_stats.last_backward_time:
                    logger.warning(
                        f"Timestamp anomaly: current_time ({current_time}) < last_backward_time ({flow_stats.last_backward_time}) for flow {flow_key}"
                    )
                iat_backward = max(0, current_time - flow_stats.last_backward_time)
                flow_stats.backward_iat.append(iat_backward)
            flow_stats.last_backward_time = current_time

        # Activity tracking with non-negative values
        time_since_last = max(0, current_time - flow_stats.last_activity)
        if time_since_last > 1.0:
            flow_stats.idle_times.append(time_since_last)
        else:
            flow_stats.active_times.append(time_since_last)
        flow_stats.last_activity = current_time

        ##Newly added code to handle TCP window size
        tcp = pkt.getlayer(TCP)
        if tcp:
            if is_forward and flow_stats.init_win_forward is None:
                flow_stats.init_win_forward = tcp.window
            elif not is_forward and flow_stats.init_win_backward is None:
                flow_stats.init_win_backward = tcp.window
        payload_len = len(pkt[TCP].payload) if pkt.haslayer(TCP) else 0
        if is_forward:
            flow_stats.forward_payload_lengths.append(payload_len)
        else:
            flow_stats.backward_payload_lengths.append(payload_len)

        # Corrected code in _update_flow_statistics method
        if is_forward:
            if flow_stats.last_forward_time is not None:
                iat = max(
                    0, current_time - flow_stats.last_forward_time
                )  # Ensure non-negative
                flow_stats.forward_iat.append(iat)
            flow_stats.last_forward_time = current_time
        else:
            if flow_stats.last_backward_time is not None:
                iat = max(
                    0, current_time - flow_stats.last_backward_time
                )  # Ensure non-negative
                flow_stats.backward_iat.append(iat)
            flow_stats.last_backward_time = current_time

        # And for the overall flow IAT:
        # if flow_packets and hasattr(flow_packets[-1], 'time'):
        #     flow_stats.flow_iat.append(current_time - flow_packets[-1].time)

        if flow_stats.last_flow_time is not None:
            if current_time < flow_stats.last_flow_time:
                logger.warning(
                    f"Timestamp anomaly: current_time ({current_time}) < last_flow_time ({flow_stats.last_flow_time}) for flow {flow_key}"
                )
            iat_flow = max(0, current_time - flow_stats.last_flow_time)
            flow_stats.flow_iat.append(iat_flow)
        flow_stats.last_flow_time = current_time

        # Update directional statistics
        if is_forward:
            flow_stats.forward_packets += 1
            flow_stats.total_length_forward += packet_metrics.size
            flow_stats.forward_packet_lengths.append(packet_metrics.size)
            flow_stats.forward_header_lengths.append(packet_metrics.header_size)
        else:
            flow_stats.backward_packets += 1
            flow_stats.total_length_backward += packet_metrics.size
            flow_stats.backward_packet_lengths.append(packet_metrics.size)
            flow_stats.backward_header_lengths.append(packet_metrics.header_size)

        # Update inter-arrival times
        if len(flow_packets) > 0:
            # General flow IAT
            if current_time < flow_packets[-1].time:
                logger.warning(
                    f"Timestamp anomaly (flow_packets general): current_time ({current_time}) < prev_packet_timestamp ({flow_packets[-1].time}) for flow {flow_key}"
                )
            iat = max(0, current_time - flow_packets[-1].time)
            flow_stats.flow_iat.append(iat)

            if is_forward:
                # Find last forward packet
                # Iterate in reverse to find the most recent packet in the same direction
                for pkt_metric in reversed(flow_packets[:-1]):  # Exclude current packet
                    # Determine direction of pkt_metric based on its relation to flow_key
                    
                    pkt_metric_is_forward = (
                        (
                            pkt[IP].src == flow_key.src_ip
                            and pkt[TCP].sport == flow_key.src_port
                        )
                        if pkt.haslayer(IP) and pkt.haslayer(TCP)
                        else False
                    )  # Default if not IP/TCP

                    if pkt_metric_is_forward:
                        if current_time < pkt_metric.timestamp:
                            logger.warning(
                                f"Timestamp anomaly (flow_packets forward): current_time ({current_time}) < pkt_metric.timestamp ({pkt_metric.timestamp}) for flow {flow_key}"
                            )
                        forward_iat = max(0, current_time - pkt_metric.timestamp)
                        flow_stats.forward_iat.append(forward_iat)
                        break
            else:  # Backward packet
                # Find last backward packet
                # Iterate in reverse to find the most recent packet in the same direction
                for pkt_metric in reversed(flow_packets[:-1]):  # Exclude current packet
                    pkt_metric_is_forward = (
                        (
                            pkt[IP].src == flow_key.src_ip
                            and pkt[TCP].sport == flow_key.src_port
                        )
                        if pkt.haslayer(IP) and pkt.haslayer(TCP)
                        else False
                    )  # Default if not IP/TCP

                    if (
                        not pkt_metric_is_forward
                    ):  # If this packet in flow_packets was backward
                        if current_time < pkt_metric.timestamp:
                            logger.warning(
                                f"Timestamp anomaly (flow_packets backward): current_time ({current_time}) < pkt_metric.timestamp ({pkt_metric.timestamp}) for flow {flow_key}"
                            )
                        backward_iat = max(0, current_time - pkt_metric.timestamp)
                        flow_stats.backward_iat.append(backward_iat)
                        break

        # Update TCP flags
        if packet_info.get("protocol") == "TCP":
            flags = packet_info.get("tcp_flags", 0)
            if not is_forward:  # Backward packet
                if flags & 0x08:  # PSH flag
                    flow_stats.backward_psh_flags += 1
                if flags & 0x20:  # URG flag
                    flow_stats.backward_urg_flags += 1
            if flags & 0x02:  # SYN
                flow_stats.syn_flag_count += 1
            if flags & 0x80 or flags & 0x40 or flags & 0x20:  # CWR, ECE, URG
                flow_stats.cwe_flag_count += 1

            # Count individual flags
            flag_names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
            for i, flag_name in enumerate(flag_names):
                if flags & (1 << i):
                    flow_stats.tcp_flags_counts[flag_name] += 1
        # Track data packets in forward direction
        if is_forward and packet_metrics.payload_size > 0:
            flow_stats.act_data_pkt_fwd += 1
        if is_forward:
            if flow_stats.min_seg_size_forward == 0:
                flow_stats.min_seg_size_forward = packet_metrics.payload_size
            else:
                flow_stats.min_seg_size_forward = min(
                    flow_stats.min_seg_size_forward, packet_metrics.payload_size
                )
        #  Capture initial window sizes during TCP handshake
        if packet_info.get("protocol") == "TCP" and flags & 0x02:  # SYN flag
            if is_forward:
                flow_stats.init_win_forward = packet_info.get("tcp_window_size", 0)
            else:
                flow_stats.init_win_backward = packet_info.get("tcp_window_size", 0)
        # Add packet to flow
        flow_packets.append(packet_metrics)

        # Limit packet history to prevent memory issues
        if len(flow_packets) > 1000:
            flow_packets.pop(0)

        # Update activity tracking
        # Corrected code in _update_flow_statistics method
        time_since_last = max(
            0, current_time - flow_stats.last_activity
        )  # Ensure non-negative
        if time_since_last > 1.0:  # 1 second threshold for idle time
            flow_stats.idle_times.append(time_since_last)
        else:
            flow_stats.active_times.append(time_since_last)

        flow_stats.last_activity = current_time

    def _compute_flow_features(
        self, flow_key: FlowKey, packet_info: Dict
    ) -> Dict[str, Any]:
        """Compute comprehensive flow features matching CICIDS datasets"""
        flow_stats = self.flows[flow_key]
        features = {}

        # Basic flow features
        features.update(
            {
                "Flow_Duration": flow_stats.duration * 1000000,  # microseconds
                "Total_Fwd_Packets": flow_stats.forward_packets,
                "Total_Backward_Packets": flow_stats.backward_packets,
                "Total_Length_of_Fwd_Packets": flow_stats.total_length_forward,
                "Total_Length_of_Bwd_Packets": flow_stats.total_length_backward,
            }
        )
        features.update(
            {
                "Bwd_PSH_Flags": flow_stats.backward_psh_flags,
                "Bwd_URG_Flags": flow_stats.backward_urg_flags,
                "act_data_pkt_fwd": flow_stats.act_data_pkt_fwd,
                "min_seg_size_forward": (
                    min(flow_stats.forward_payload_lengths)
                    if flow_stats.forward_payload_lengths
                    else 0
                ),
                "min_seg_size_backward": (
                    min(flow_stats.backward_payload_lengths)
                    if flow_stats.backward_payload_lengths
                    else 0
                ),
                "Init_Win_bytes_forward": flow_stats.init_win_forward,
                "Init_Win_bytes_backward": flow_stats.init_win_backward,
            }
        )
        # Packet length statistics
        all_lengths = (
            flow_stats.forward_packet_lengths + flow_stats.backward_packet_lengths
        )
        if all_lengths:
            features.update(
                {
                    "Fwd_Packet_Length_Max": (
                        max(flow_stats.forward_packet_lengths)
                        if flow_stats.forward_packet_lengths
                        else 0
                    ),
                    "Fwd_Packet_Length_25th": (
                        np.percentile(flow_stats.forward_packet_lengths, 25)
                        if flow_stats.forward_packet_lengths
                        else 0
                    ),
                    "Fwd_Packet_Length_50th": (
                        np.percentile(flow_stats.forward_packet_lengths, 50)
                        if flow_stats.forward_packet_lengths
                        else 0
                    ),
                    "Fwd_Packet_Length_75th": (
                        np.percentile(flow_stats.forward_packet_lengths, 75)
                        if flow_stats.forward_packet_lengths
                        else 0
                    ),
                    "Fwd_Packet_Length_Min": (
                        min(flow_stats.forward_packet_lengths)
                        if flow_stats.forward_packet_lengths
                        else 0
                    ),
                    "Fwd_Packet_Length_Mean": (
                        statistics.mean(flow_stats.forward_packet_lengths)
                        if flow_stats.forward_packet_lengths
                        else 0
                    ),
                    "Fwd_Packet_Length_Std": (
                        statistics.stdev(flow_stats.forward_packet_lengths)
                        if len(flow_stats.forward_packet_lengths) > 1
                        else 0
                    ),
                    "Bwd_Packet_Length_Max": (
                        max(flow_stats.backward_packet_lengths)
                        if flow_stats.backward_packet_lengths
                        else 0
                    ),
                    "Bwd_Packet_Length_Min": (
                        min(flow_stats.backward_packet_lengths)
                        if flow_stats.backward_packet_lengths
                        else 0
                    ),
                    "Bwd_Packet_Length_Mean": (
                        statistics.mean(flow_stats.backward_packet_lengths)
                        if flow_stats.backward_packet_lengths
                        else 0
                    ),
                    "Bwd_Packet_Length_25th": (
                        np.percentile(flow_stats.backward_packet_lengths, 25)
                        if flow_stats.backward_packet_lengths
                        else 0
                    ),
                    "Bwd_Packet_Length_50th": (
                        np.percentile(flow_stats.backward_packet_lengths, 50)
                        if flow_stats.backward_packet_lengths
                        else 0
                    ),
                    "Bwd_Packet_Length_75th": (
                        np.percentile(flow_stats.backward_packet_lengths, 75)
                        if flow_stats.backward_packet_lengths
                        else 0
                    ),
                    "Bwd_Packet_Length_Std": (
                        statistics.stdev(flow_stats.backward_packet_lengths)
                        if len(flow_stats.backward_packet_lengths) > 1
                        else 0
                    ),
                }
            )

        # Flow bytes/packets per second
        if flow_stats.duration > 0:
            features.update(
                {
                    "Flow_Bytes_s": (
                        flow_stats.total_length_forward
                        + flow_stats.total_length_backward
                    )
                    / flow_stats.duration,
                    "Flow_Packets_s": flow_stats.total_packets / flow_stats.duration,
                    "Flow_IAT_Mean": (
                        statistics.mean(flow_stats.flow_iat)
                        if flow_stats.flow_iat
                        else 0
                    ),
                    "Flow_IAT_25th": (
                        np.percentile(flow_stats.flow_iat, 25)
                        if flow_stats.flow_iat
                        else 0
                    ),
                    "Flow_IAT_50th": (
                        np.percentile(flow_stats.flow_iat, 50)
                        if flow_stats.flow_iat
                        else 0
                    ),
                    "Flow_IAT_75th": (
                        np.percentile(flow_stats.flow_iat, 75)
                        if flow_stats.flow_iat
                        else 0
                    ),
                    "Flow_IAT_Std": (
                        statistics.stdev(flow_stats.flow_iat)
                        if len(flow_stats.flow_iat) > 1
                        else 0
                    ),
                    "Flow_IAT_Max": (
                        max(flow_stats.flow_iat) if flow_stats.flow_iat else 0
                    ),
                    "Flow_IAT_Min": (
                        min(flow_stats.flow_iat) if flow_stats.flow_iat else 0
                    ),
                }
            )

        # Forward/Backward IAT statistics
        if flow_stats.forward_iat:
            features.update(
                {
                    "Fwd_IAT_Total": sum(flow_stats.forward_iat),
                    "Fwd_IAT_Mean": statistics.mean(flow_stats.forward_iat),
                    "Fwd_IAT_Std": (
                        statistics.stdev(flow_stats.forward_iat)
                        if len(flow_stats.forward_iat) > 1
                        else 0
                    ),
                    "Fwd_IAT_Max": max(flow_stats.forward_iat),
                    "Fwd_IAT_Min": min(flow_stats.forward_iat),
                }
            )

        if flow_stats.backward_iat:
            features.update(
                {
                    "Bwd_IAT_Total": sum(flow_stats.backward_iat),
                    "Bwd_IAT_Mean": statistics.mean(flow_stats.backward_iat),
                    "Bwd_IAT_Std": (
                        statistics.stdev(flow_stats.backward_iat)
                        if len(flow_stats.backward_iat) > 1
                        else 0
                    ),
                    "Bwd_IAT_Max": max(flow_stats.backward_iat),
                    "Bwd_IAT_Min": min(flow_stats.backward_iat),
                }
            )

        # TCP Flag features
        features.update(
            {
                "FIN_Flag_Count": flow_stats.tcp_flags_counts.get("FIN", 0),
                "SYN_Flag_Count": flow_stats.tcp_flags_counts.get("SYN", 0),
                "RST_Flag_Count": flow_stats.tcp_flags_counts.get("RST", 0),
                "PSH_Flag_Count": flow_stats.tcp_flags_counts.get("PSH", 0),
                "ACK_Flag_Count": flow_stats.tcp_flags_counts.get("ACK", 0),
                "URG_Flag_Count": flow_stats.tcp_flags_counts.get("URG", 0),
                "CWE_Flag_Count": flow_stats.cwe_flag_count,
                "ECE_Flag_Count": flow_stats.tcp_flags_counts.get("ECE", 0),
            }
        )

        # Header length statistics
        if flow_stats.forward_header_lengths:
            features["Fwd_Header_Length"] = statistics.mean(
                flow_stats.forward_header_lengths
            )
        if flow_stats.backward_header_lengths:
            features["Bwd_Header_Length"] = statistics.mean(
                flow_stats.backward_header_lengths
            )

        # Packets per second features
        if flow_stats.duration > 0:
            features.update(
                {
                    "Fwd_Packets_s": flow_stats.forward_packets / flow_stats.duration,
                    "Bwd_Packets_s": flow_stats.backward_packets / flow_stats.duration,
                }
            )

        # Packet size ratios and statistics
        total_packets = flow_stats.total_packets
        if total_packets > 0:
            features.update(
                {
                    "Down_Up_Ratio": flow_stats.backward_packets
                    / max(flow_stats.forward_packets, 1),
                    "Average_Packet_Size": (
                        flow_stats.total_length_forward
                        + flow_stats.total_length_backward
                    )
                    / total_packets,
                    "Avg_Fwd_Segment_Size": flow_stats.total_length_forward
                    / max(flow_stats.forward_packets, 1),
                    "Avg_Bwd_Segment_Size": flow_stats.total_length_backward
                    / max(flow_stats.backward_packets, 1),
                }
            )

        # Active/Idle time features
        if flow_stats.active_times:
            features.update(
                {
                    "Active_Mean": statistics.mean(flow_stats.active_times),
                    "Active_Std": (
                        statistics.stdev(flow_stats.active_times)
                        if len(flow_stats.active_times) > 1
                        else 0
                    ),
                    "Active_Max": max(flow_stats.active_times),
                    "Active_Min": min(flow_stats.active_times),
                }
            )

        if flow_stats.idle_times:
            features.update(
                {
                    "Idle_Mean": statistics.mean(flow_stats.idle_times),
                    "Idle_Std": (
                        statistics.stdev(flow_stats.idle_times)
                        if len(flow_stats.idle_times) > 1
                        else 0
                    ),
                    "Idle_Max": max(flow_stats.idle_times),
                    "Idle_Min": min(flow_stats.idle_times),
                }
            )

        # Subflow features (simplified - can be expanded)
        features.update(
            {
                "Subflow_Fwd_Packets": flow_stats.forward_packets,
                "Subflow_Fwd_Bytes": flow_stats.total_length_forward,
                "Subflow_Bwd_Packets": flow_stats.backward_packets,
                "Subflow_Bwd_Bytes": flow_stats.total_length_backward,
            }
        )

        return features

    def _extract_behavioral_features(self, packet_info: Dict) -> Dict[str, Any]:
        """Extract behavioral features for anomaly detection"""
        src_ip = packet_info.get("src_ip")
        dst_ip = packet_info.get("dst_ip")
        src_port = packet_info.get("src_port", 0)
        dst_port = packet_info.get("dst_port", 0)
        protocol = packet_info.get("protocol", "Other")

        behavior = self.ip_behavior[src_ip]

        # Update behavioral tracking
        behavior["connection_attempts"] += 1
        behavior["unique_destinations"].add(dst_ip)
        behavior["protocols_used"].add(protocol)
        behavior["packet_sizes"].append(packet_info["size"])
        behavior["request_rates"].append(time.time())

        # Port scanning detection
        if dst_port > 0:
            behavior["port_scan_attempts"].add((dst_ip, dst_port))

        # Calculate behavioral features
        current_time = time.time()
        time_window = current_time - behavior["first_seen"]

        features = {
            "unique_destinations_count": len(behavior["unique_destinations"]),
            "protocols_count": len(behavior["protocols_used"]),
            "connection_rate": behavior["connection_attempts"] / max(time_window, 1),
            "port_scan_score": len(behavior["port_scan_attempts"]),
            "packet_size_variance": (
                statistics.variance(behavior["packet_sizes"][-100:])
                if len(behavior["packet_sizes"]) > 1
                else 0
            ),
        }

        # Request rate in last minute
        recent_requests = [
            t for t in behavior["request_rates"] if current_time - t <= 60
        ]
        features["requests_per_minute"] = len(recent_requests)

        return features

    def _extract_protocol_features(
        self, packet: Packet, packet_info: Dict
    ) -> Dict[str, Any]:
        """Extract protocol-specific features"""
        features = {}

        # HTTP-specific features
        if packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
            features.update(self._extract_http_features(packet))

        # DNS-specific features
        if packet.haslayer(DNS):
            features.update(self._extract_dns_features(packet))

        # TCP-specific advanced features
        if packet.haslayer(TCP):
            features.update(self._extract_tcp_advanced_features(packet))

        return features

    def _extract_http_features(self, packet: Packet) -> Dict[str, Any]:
        """Extract HTTP-specific features"""
        features = {}

        if packet.haslayer(HTTPRequest):
            req = packet[HTTPRequest]
            features.update(
                {
                    "http_method": (
                        req.Method.decode("utf-8", errors="ignore")
                        if req.Method
                        else ""
                    ),
                    "http_uri_length": (
                        len(req.Path.decode("utf-8", errors="ignore"))
                        if req.Path
                        else 0
                    ),
                    "http_user_agent_length": (
                        len(req.User_Agent.decode("utf-8", errors="ignore"))
                        if req.User_Agent
                        else 0
                    ),
                    "http_host_length": (
                        len(req.Host.decode("utf-8", errors="ignore"))
                        if req.Host
                        else 0
                    ),
                }
            )

        if packet.haslayer(HTTPResponse):
            resp = packet[HTTPResponse]
            if hasattr(resp, "Status_Code"):
                features["http_status_code"] = int(
                    resp.Status_Code.decode("utf-8", errors="ignore")
                )

        return features

    def _extract_dns_features(self, packet: Packet) -> Dict[str, Any]:
        """Extract DNS-specific features"""
        features = {}
        dns = packet[DNS]

        features.update(
            {
                "dns_query_count": dns.qdcount,
                "dns_answer_count": dns.ancount,
                "dns_authority_count": dns.nscount,
                "dns_additional_count": dns.arcount,
                "dns_query_type": dns.qd.qtype if dns.qd else 0,
            }
        )

        return features

    def _extract_tcp_advanced_features(self, packet: Packet) -> Dict[str, Any]:
        """Extract advanced TCP features"""
        features = {}
        tcp = packet[TCP]

        features.update(
            {
                "tcp_window_size": tcp.window,
                "tcp_urgent_pointer": tcp.urgptr,
                "tcp_sequence_number": tcp.seq,
                "tcp_acknowledgment_number": tcp.ack,
                "tcp_reserved_bits": (tcp.reserved << 1) | ((tcp.flags >> 8) & 1),
                "tcp_checksum": tcp.chksum,
                "tcp_options_count": len(tcp.options) if tcp.options else 0,
            }
        )

        return features

    def _cleanup_old_flows(self):
        """Remove old flows to prevent memory leaks"""
        current_time = time.time()
        flows_to_remove = []

        for flow_key, flow_stats in self.flows.items():
            if current_time - flow_stats.last_seen > self.flow_timeout:
                flows_to_remove.append(flow_key)

        for flow_key in flows_to_remove:
            del self.flows[flow_key]
            if flow_key in self.flow_packets:
                del self.flow_packets[flow_key]

        self.last_cleanup = current_time
        logger.debug(f"Cleaned up {len(flows_to_remove)} old flows")

    def _append_features_row(self, filename: str, features: Dict[str, Any]):
        fieldnames = list(features.keys())
        write_header = not os.path.exists(filename) or os.path.getsize(filename) == 0
        with open(filename, "a", newline="") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            if write_header:
                writer.writeheader()
            writer.writerow(features)

    def get_flow_summary(self, flow_key: FlowKey) -> Dict[str, Any]:
        """Get comprehensive flow summary for threat detection"""
        if flow_key not in self.flows:
            return {}

        flow_stats = self.flows[flow_key]
        packets = self.flow_packets.get(flow_key, [])

        summary = {
            "flow_key": {
                "src_ip": flow_key.src_ip,
                "dst_ip": flow_key.dst_ip,
                "src_port": flow_key.src_port,
                "dst_port": flow_key.dst_port,
                "protocol": flow_key.protocol,
            },
            "duration": flow_stats.duration,
            "total_packets": flow_stats.total_packets,
            "total_bytes": flow_stats.total_length_forward
            + flow_stats.total_length_backward,
            "packets_per_second": flow_stats.total_packets
            / max(flow_stats.duration, 1),
            "bytes_per_second": (
                flow_stats.total_length_forward + flow_stats.total_length_backward
            )
            / max(flow_stats.duration, 1),
            "forward_backward_ratio": flow_stats.forward_packets
            / max(flow_stats.backward_packets, 1),
            "avg_packet_size": (
                flow_stats.total_length_forward + flow_stats.total_length_backward
            )
            / max(flow_stats.total_packets, 1),
            "tcp_flags_diversity": len(
                [f for f, c in flow_stats.tcp_flags_counts.items() if c > 0]
            ),
            "is_suspicious": self._assess_flow_suspicion(flow_stats, packets),
        }

        return summary

    def _assess_flow_suspicion(
        self, flow_stats: FlowStatistics, packets: List[PacketMetrics]
    ) -> bool:
        """Assess if a flow shows suspicious characteristics"""
        suspicion_score = 0

        # High packet rate
        if flow_stats.duration > 0:
            pps = flow_stats.total_packets / flow_stats.duration
            if pps > 100:  # More than 100 packets per second
                suspicion_score += 2

        # Unusual packet sizes
        all_sizes = (
            flow_stats.forward_packet_lengths + flow_stats.backward_packet_lengths
        )
        if all_sizes:
            avg_size = statistics.mean(all_sizes)
            if avg_size < 64 or avg_size > 1400:  # Very small or large packets
                suspicion_score += 1

        # TCP flag anomalies
        if flow_stats.syn_flag_count > 10:  # Multiple SYN packets
            suspicion_score += 2
        if flow_stats.tcp_flags_counts.get("RST", 0) > 5:  # Multiple resets
            suspicion_score += 1

        # Port scanning indicators
        if len(packets) > 0:
            unique_ports = set()
            for i, pkt in enumerate(packets[-50:]):  # Check last 50 packets
                if hasattr(pkt, "dst_port"):
                    unique_ports.add(pkt.dst_port)
            if len(unique_ports) > 20:  # Accessing many different ports
                suspicion_score += 3

        # Unusual timing patterns
        if flow_stats.flow_iat:
            iat_variance = (
                statistics.variance(flow_stats.flow_iat)
                if len(flow_stats.flow_iat) > 1
                else 0
            )
            if iat_variance < 0.001:  # Very regular timing (possible automation)
                suspicion_score += 1

        return suspicion_score >= 3

    def get_real_time_features(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """Get features optimized for real-time prediction"""
        features = self.extract_features(packet)
        if not features:
            return None

        # Select most important features for real-time prediction
        important_features = [
            "Flow_Duration",
            "Total_Fwd_Packets",
            "Total_Backward_Packets",
            "Total_Length_of_Fwd_Packets",
            "Total_Length_of_Bwd_Packets",
            "Fwd_Packet_Length_Max",
            "Fwd_Packet_Length_Mean",
            "Fwd_Packet_Length_Std",
            "Bwd_Packet_Length_Max",
            "Bwd_Packet_Length_Mean",
            "Bwd_Packet_Length_Std",
            "Flow_Bytes_s",
            "Flow_Packets_s",
            "Flow_IAT_Mean",
            "Flow_IAT_25th",
            "Flow_IAT_50th",
            "Flow_IAT_75th",
            "Flow_IAT_Std",
            "Fwd_IAT_Mean",
            "Bwd_IAT_Mean",
            "SYN_Flag_Count",
            "RST_Flag_Count",
            "PSH_Flag_Count",
            "ACK_Flag_Count",
            "URG_Flag_Count",
            "CWE_Flag_Count",
            "Fwd_Packet_Length_25th",
            "Fwd_Packet_Length_50th",
            "Fwd_Packet_Length_75th",
            "Bwd_Packet_Length_25th",
            "Bwd_Packet_Length_50th",
            "Bwd_Packet_Length_75th",
            "Down_Up_Ratio",
            "Average_Packet_Size",
            "unique_destinations_count",
            "connection_rate",
            "port_scan_score",
            "requests_per_minute",
        ]

        # Create feature vector with only important features
        feature_vector = {}
        for feature_name in important_features:
            feature_vector[feature_name] = features.get(feature_name, 0)

        # Add packet-level features for immediate detection
        packet_info = self._extract_basic_info(packet)
        if packet_info:
            feature_vector.update(
                {
                    "packet_size": packet_info["size"],
                    "payload_size": packet_info.get("payload_size", 0),
                    "header_size": packet_info.get("header_size", 0),
                    "protocol_numeric": self._protocol_to_numeric(
                        packet_info.get("protocol", "Other")
                    ),
                    "src_port": packet_info.get("src_port", 0),
                    "dst_port": packet_info.get("dst_port", 0),
                    "is_common_port": self._is_common_port(
                        packet_info.get("dst_port", 0)
                    ),
                    "timestamp": packet_info.get("timestamp", time.time()),
                }
            )

        return feature_vector

    def _protocol_to_numeric(self, protocol: str) -> int:
        """Convert protocol string to numeric value"""
        protocol_map = {
            "TCP": 1,
            "UDP": 2,
            "ICMP": 3,
            "ARP": 4,
            "HTTP": 5,
            "HTTPS": 6,
            "DNS": 7,
            "FTP": 8,
            "SSH": 9,
            "TELNET": 10,
            "SMTP": 11,
            "Other": 0,
        }
        return protocol_map.get(protocol, 0)

    def _is_common_port(self, port: int) -> int:
        """Check if port is commonly used (1) or uncommon (0)"""
        common_ports = {
            20,
            21,
            22,
            23,
            25,
            53,
            67,
            68,
            80,
            110,
            119,
            123,
            143,
            161,
            194,
            220,
            443,
            465,
            587,
            993,
            995,
            3389,
            5432,
            3306,
        }
        return 1 if port in common_ports else 0

    def export_features_csv(self, filename: str, max_flows: int = 1000):
        """Export current flow features to CSV for model training"""
        import csv
        import os

        with self.lock:  # Thread-safe access
            flows_to_export = list(self.flows.items())[:max_flows]  # Copy current state
            if not flows_to_export:
                logger.warning("No flows to export")
                return

        file_exists = os.path.isfile(filename)

        with open(filename, "a", newline="") as csvfile:  # Append mode
            # Get fieldnames from first flow
            sample_flow_key, _ = flows_to_export[0]
            packet_info = {
                "src_ip": sample_flow_key.src_ip,
                "dst_ip": sample_flow_key.dst_ip,
                "src_port": sample_flow_key.src_port,
                "dst_port": sample_flow_key.dst_port,
                "protocol": sample_flow_key.protocol,
            }
            sample_features = self._compute_flow_features(sample_flow_key, packet_info)
            fieldnames = list(sample_features.keys()) + ["Label"]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Write header only once
            if not file_exists or os.path.getsize(filename) == 0:
                writer.writeheader()

            # Write rows
            count = 0
            for flow_key, _ in flows_to_export:
                packet_info = {
                    "src_ip": flow_key.src_ip,
                    "dst_ip": flow_key.dst_ip,
                    "src_port": flow_key.src_port,
                    "dst_port": flow_key.dst_port,
                    "protocol": flow_key.protocol,
                }
                features = self._compute_flow_features(flow_key, packet_info)
                features = self._ensure_data_types(features)
                features["Label"] = "BENIGN"
                writer.writerow(features)
                count += 1

        logger.info(f"Appended {count} flows to {filename}")

    def _ensure_data_types(self, features: Dict[str, Any]) -> Dict[str, Any]:
        return {
            k: (float(v) if isinstance(v, (int, float)) else 0.0)
            for k, v in features.items()
            if k != "Label"
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get current extractor statistics"""
        total_flows = len(self.flows)
        total_ips = len(self.ip_behavior)

        if total_flows > 0:
            avg_flow_duration = statistics.mean(
                [f.duration for f in self.flows.values()]
            )
            avg_packets_per_flow = statistics.mean(
                [f.total_packets for f in self.flows.values()]
            )
        else:
            avg_flow_duration = 0
            avg_packets_per_flow = 0

        return {
            "total_flows": total_flows,
            "total_tracked_ips": total_ips,
            "avg_flow_duration": avg_flow_duration,
            "avg_packets_per_flow": avg_packets_per_flow,
            "memory_usage_flows": len(self.flows),
            "memory_usage_packets": sum(
                len(packets) for packets in self.flow_packets.values()
            ),
            "last_cleanup": self.last_cleanup,
        }

    def reset(self):
        """Reset all tracked flows and statistics"""
        with self.lock:
            self.flows.clear()
            self.flow_packets.clear()
            self.ip_behavior.clear()
            logger.info("Feature extractor reset completed")


class ThreatDetector:
    """Real-time threat detection using extracted features"""

    def __init__(
        self, feature_extractor: AdvancedFeatureExtractor, sio_queue: Queue = None
    ):
        self.feature_extractor = feature_extractor
        self.sio_queue = sio_queue  # Optional Socket.IO queue for real-time updates
        self.threat_thresholds = {
            "port_scan_threshold": 50,
            "high_packet_rate": 100,
            "suspicious_packet_size": (0, 64, 1400, 9000),
            "connection_rate_threshold": 10,
            "syn_flood_threshold": 20,
            "dns_amplification_threshold": 100,
        }

        self.detected_threats = deque(maxlen=1000)
        self.threat_stats = defaultdict(int)

    def detect_threats(self, packet: Packet) -> List[Dict[str, Any]]:
        """Detect threats with full context: port, service, severity, and user actions."""
        threats = []

        # === Step 1: Extract features ===
        features = self.feature_extractor.get_real_time_features(packet)
        if not features:
            return threats

        total_packets = features.get("Total_Fwd_Packets", 0) + features.get(
            "Total_Backward_Packets", 0
        )
        flow_duration = features.get("Flow_Duration", 0)
        pps = features.get("Flow_Packets_s", 0)
        syn_count = features.get("SYN_Flag_Count", 0)
        port_scan_score = features.get("port_scan_score", 0)
        dst_port = features.get("dst_port", 0)
        src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
        timestamp = time.time()
        packet_size = features.get("packet_size", 0)
        is_dns_amp = (
            packet.haslayer(UDP)
            and packet.haslayer(DNS)
            and packet[UDP].dport == 53
            and len(packet) > 512
        )

        # === Step 2: Critical ports & services ===
        critical_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP-ALT",
        }
        service = critical_ports.get(dst_port, "Unknown")
        is_critical = dst_port in critical_ports

        # === Step 3: Evidence filter ===
        if total_packets < 5 or flow_duration < 1.0:
            return threats

        # === Step 4: Attack Detection Rules ===

        # 4.1 Port Scan
        if port_scan_score > self.threat_thresholds.get("port_scan_threshold", 10):
            threats.append(
                {
                    "type": "PORT_SCAN",
                    "severity": "HIGH" if is_critical else "MEDIUM",
                    "confidence": 0.95,
                    "details": f"Scan on {service} (port {dst_port}) - score {port_scan_score}",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "service": service,
                    "actions": ["block_port" if is_critical else "notify_user"],
                    "timestamp": timestamp,
                }
            )

        # 4.2 DDoS (High packet rate)
        if pps > self.threat_thresholds.get("high_packet_rate", 500):
            threats.append(
                {
                    "type": "DDOS_ATTACK",
                    "severity": "CRITICAL" if is_critical else "HIGH",
                    "confidence": 0.9,
                    "details": f"High packet rate: {pps:.2f} pps targeting {service} (port {dst_port})",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "service": service,
                    "actions": ["block_ip", "notify_user"],
                    "timestamp": timestamp,
                }
            )

        # 4.3 SYN Flood
        if syn_count > self.threat_thresholds.get("syn_flood_threshold", 100):
            threats.append(
                {
                    "type": "SYN_FLOOD",
                    "severity": "HIGH",
                    "confidence": 0.85,
                    "details": f"{syn_count} SYN packets to {service} (port {dst_port})",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "service": service,
                    "actions": ["block_ip", "notify_user"],
                    "timestamp": timestamp,
                }
            )

        # 4.4 Suspicious Packet Size
        if total_packets >= 5 and (packet_size < 64 or packet_size > 1400):
            threats.append(
                {
                    "type": "SUSPICIOUS_PACKET_SIZE",
                    "severity": "MEDIUM",
                    "confidence": 0.65,
                    "details": f"Suspicious size: {packet_size} bytes on {service} (port {dst_port})",
                    "src_ip": src_ip,
                    "dst_port": dst_port,
                    "service": service,
                    "actions": ["monitor_flow"],
                    "timestamp": timestamp,
                }
            )

        # 4.5 DNS Amplification
        if is_dns_amp:
            threats.append(
                {
                    "type": "DNS_AMPLIFICATION",
                    "severity": "HIGH",
                    "confidence": 0.8,
                    "details": f"DNS response >512 bytes: {len(packet)} bytes",
                    "src_ip": src_ip,
                    "dst_port": 53,
                    "service": "DNS",
                    "actions": ["block_ip", "notify_user"],
                    "timestamp": timestamp,
                }
            )

        # === Step 5: Emit and store threats ===
        for threat in threats:
            self.detected_threats.append(threat)
            self.threat_stats[threat["type"]] += 1
            logger.warning(
                f"THREAT DETECTED: {threat['type']} from {threat['src_ip']} → {threat['service']}:{threat['dst_port']} - {threat['details']}"
            )

            # Send to frontend via Socket.IO (if configured)
            if self.sio_queue:
                self.sio_queue.put_nowait(("threat_detected", threat))

        return threats

    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of detected threats"""
        recent_threats = [
            t for t in self.detected_threats if time.time() - t["timestamp"] <= 3600
        ]  # Last hour

        return {
            "total_threats_detected": len(self.detected_threats),
            "threats_last_hour": len(recent_threats),
            "threat_types": dict(self.threat_stats),
            "most_recent_threats": (
                list(self.detected_threats)[-10:] if self.detected_threats else []
            ),
        }


# Usage example for integration with your packet sniffer
class EnhancedPacketProcessor:
    """Enhanced packet processor with feature extraction and threat detection"""

    def __init__(self):
        self.feature_extractor = AdvancedFeatureExtractor()
        self.threat_detector = ThreatDetector(self.feature_extractor)
        self._pkt_counts: Dict[FlowKey, int] = defaultdict(int)
        self.prediction_model = None  # Placeholder for ML model

    def load_model(self, model_path: str):
        """Load pre-trained threat detection model"""
        # Placeholder for model loading
        # Example: self.prediction_model = joblib.load(model_path)
        pass

    def process_packet(self, packet: Packet) -> None:
        # Generate a unique flow key for this packet
        flow_key = self.feature_extractor.flow_key(packet)

        # Update packet count for the flow
        self._pkt_counts[flow_key] += 1

        # Feed the packet to the feature extractor for real-time updates
        self.feature_extractor.update_flow(packet)

        # Check if this packet contains a FIN or RST flag to mark end of flow
        tcp = packet.getlayer(TCP)
        if tcp and (tcp.flags & (0x01 | 0x04)):  # FIN=0x01, RST=0x04
            # Compute final flow features
            features = self.feature_extractor.compute_features(
                flow_key, pkt_count=self._pkt_counts[flow_key]
            )

            # If features are computed successfully, append them to CSV
            if features:
                self.feature_extractor._append_features_row(
                    "ml_ready_features.csv", features
                )

            # Clear flow-specific data to free memory
            self.feature_extractor.clear_flow(flow_key)
            del self._pkt_counts[flow_key]

    def prepare_feature_vector(self, features: Dict[str, Any]) -> List[float]:
        """Prepare feature vector for ML model in the exact order used during training."""
        # This should match the exact order from your training DataFrame
        expected_features = [
            "Flow_Duration",  # 0
            "Total_Fwd_Packets",  # 1
            "Total_Backward_Packets",  # 2
            "Total_Length_of_Fwd_Packets",  # 3
            "Total_Length_of_Bwd_Packets",  # 4
            "Fwd_Packet_Length_Max",  # 5
            "Fwd_Packet_Length_Min",  # 6
            "Fwd_Packet_Length_Mean",  # 7
            "Fwd_Packet_Length_Std",  # 8
            "Bwd_Packet_Length_Max",  # 9
            "Bwd_Packet_Length_Min",  # 10
            "Bwd_Packet_Length_Mean",  # 11
            "Bwd_Packet_Length_Std",  # 12
            "Flow_Bytes_s",  # 13
            "Flow_Packets_s",  # 14
            "Flow_IAT_Mean",  # 15
            "Flow_IAT_Std",  # 16
            "Flow_IAT_Max",  # 17
            "Flow_IAT_Min",  # 18
            "Fwd_IAT_Total",  # 19
            "Fwd_IAT_Mean",  # 20
            "Fwd_IAT_Std",  # 21
            "Fwd_IAT_Max",  # 22
            "Fwd_IAT_Min",  # 23
            "Bwd_IAT_Total",  # 24
            "Bwd_IAT_Mean",  # 25
            "Bwd_IAT_Std",  # 26
            "Bwd_IAT_Max",  # 27
            "Bwd_IAT_Min",  # 28
            "Fwd_PSH_Flags",  # 29
            "Bwd_PSH_Flags",  # 30
            "Fwd_URG_Flags",  # 31
            "Bwd_URG_Flags",  # 32
            "Fwd_Header_Length",  # 33
            "Bwd_Header_Length",  # 34
            "Fwd_Packets_s",  # 35
            "Bwd_Packets_s",  # 36
            "FIN_Flag_Count",  # 37
            "SYN_Flag_Count",  # 38
            "RST_Flag_Count",  # 39
            "PSH_Flag_Count",  # 40
            "ACK_Flag_Count",  # 41
            "URG_Flag_Count",  # 42
            "CWE_Flag_Count",  # 43
            "ECE_Flag_Count",  # 44
            "Down_Up_Ratio",  # 45
            "Average_Packet_Size",  # 46
            "Avg_Fwd_Segment_Size",  # 47
            "Avg_Bwd_Segment_Size",  # 48
            "Subflow_Fwd_Packets",  # 49
            "Subflow_Fwd_Bytes",  # 50
            "Subflow_Bwd_Packets",  # 51
            "Subflow_Bwd_Bytes",  # 52
            "Init_Win_bytes_forward",  # 53
            "Init_Win_bytes_backward",  # 54
            "act_data_pkt_fwd",  # 55
            "min_seg_size_forward",  # 56
            "Active_Mean",  # 57
            "Active_Std",  # 58
            "Active_Max",  # 59
            "Active_Min",  # 60
            "Idle_Mean",  # 61
            "Idle_Std",  # 62
            "Idle_Max",  # 63
            "Idle_Min",  # 64
        ]

        vector = []
        for feat in expected_features:
            raw = features.get(feat, 0.0)
            try:
                val = float(raw)
            except (TypeError, ValueError):
                val = 0.0
            vector.append(val)

        return vector

    # x_raw = self._prepare_feature_vector(features)
    # x_scaled = preprocessor.transform([x_raw])
    # pred = model.decision_function(x_scaled)  # or predict_proba, etc.

    def _ensure_data_types(self, features: Dict[str, Any]) -> Dict[str, Any]:
        return {
            k: (float(v) if isinstance(v, (int, float)) else 0.0)
            for k, v in features.items()
            if k != "Label"
        }

    @staticmethod
    def json_to_custom_csv(json_path, csv_path):
        # Define column order exactly matching your features
        COLUMN_ORDER = [
            "Flow_Duration",
            "Total_Fwd_Packets",
            "Total_Backward_Packets",
            "Total_Length_of_Fwd_Packets",
            "Total_Length_of_Bwd_Packets",
            "Bwd_PSH_Flags",
            "Bwd_URG_Flags",
            "act_data_pkt_fwd",
            "min_seg_size_forward",
            "Init_Win_bytes_forward",
            "Init_Win_bytes_backward",
            "Fwd_Packet_Length_Max",
            "Fwd_Packet_Length_25th",
            "Fwd_Packet_Length_50th",
            "Fwd_Packet_Length_75th",
            "Fwd_Packet_Length_Min",
            "Fwd_Packet_Length_Mean",
            "Fwd_Packet_Length_Std",
            "Bwd_Packet_Length_Max",
            "Bwd_Packet_Length_Min",
            "Bwd_Packet_Length_Mean",
            "Bwd_Packet_Length_25th",
            "Bwd_Packet_Length_50th",
            "Bwd_Packet_Length_75th",
            "Bwd_Packet_Length_Std",
            "Flow_Bytes_s",
            "Flow_Packets_s",
            "Flow_IAT_Mean",
            "Flow_IAT_25th",
            "Flow_IAT_50th",
            "Flow_IAT_75th",
            "Flow_IAT_Std",
            "Flow_IAT_Max",
            "Flow_IAT_Min",
            "Fwd_IAT_Total",
            "Fwd_IAT_Mean",
            "Fwd_IAT_Std",
            "Fwd_IAT_Max",
            "Fwd_IAT_Min",
            "Bwd_IAT_Total",
            "Bwd_IAT_Mean",
            "Bwd_IAT_Std",
            "Bwd_IAT_Max",
            "Bwd_IAT_Min",
            "FIN_Flag_Count",
            "SYN_Flag_Count",
            "RST_Flag_Count",
            "PSH_Flag_Count",
            "ACK_Flag_Count",
            "URG_Flag_Count",
            "CWE_Flag_Count",
            "ECE_Flag_Count",
            "Fwd_Header_Length",
            "Bwd_Header_Length",
            "Fwd_Packets_s",
            "Bwd_Packets_s",
            "Down_Up_Ratio",
            "Average_Packet_Size",
            "Avg_Fwd_Segment_Size",
            "Avg_Bwd_Segment_Size",
            "Active_Mean",
            "Active_Std",
            "Active_Max",
            "Active_Min",
            "Subflow_Fwd_Packets",
            "Subflow_Fwd_Bytes",
            "Subflow_Bwd_Packets",
            "Subflow_Bwd_Bytes",
            "unique_destinations_count",
            "protocols_count",
            "connection_rate",
            "port_scan_score",
            "packet_size_variance",
            "requests_per_minute",
            "tcp_window_size",
            "tcp_urgent_pointer",
            "tcp_sequence_number",
            "tcp_acknowledgment_number",
            "tcp_reserved_bits",
            "tcp_checksum",
            "tcp_options_count",
            "Label",
        ]

        with open(json_path) as f:
            features_list = json.load(f)

        # Process each feature set
        processed = []
        for feat in features_list:
            ordered = OrderedDict()
            for col in COLUMN_ORDER:
                if col == "Label":  # Handle label separately
                    ordered[col] = feat.get(col, "BENIGN")
                else:
                    # Convert to appropriate type
                    value = feat.get(col, 0)
                    if isinstance(value, float):
                        ordered[col] = round(value, 6)
                    else:
                        ordered[col] = value
            processed.append(ordered)

        # Write to CSV
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=COLUMN_ORDER)
            writer.writeheader()
            writer.writerows(processed)

    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        return {
            "feature_extractor_stats": self.feature_extractor.get_statistics(),
            "threat_summary": self.threat_detector.get_threat_summary(),
            "model_loaded": self.prediction_model is not None,
        }
