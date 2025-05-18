#!/usr/bin/env python3
"""
Advanced Network Packet Sniffer
-------------------------------
A comprehensive network packet sniffer that captures, analyzes, and displays 
network packets in real-time using Scapy, multiprocessing, and Socket.IO for 
real-time frontend communication.
"""

import argparse
import multiprocessing
import time
import json
import signal
import sys
import os
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any, Optional

# Third-party imports
from scapy.all import (
    sniff, IP, TCP, UDP, ICMP, ARP, Ether, Dot11, DNS, 
    http, Raw, conf, get_if_list, get_if_addr
)
from flask import Flask, render_template, request
from flask_socketio import SocketIO
import psutil
import netifaces


# Global variables
running = multiprocessing.Value('b', True)
packet_queue = multiprocessing.Queue()
statistics = {
    'packet_count': multiprocessing.Value('i', 0),
    'bytes_captured': multiprocessing.Value('i', 0),
    'start_time': time.time()
}

protocol_counters = defaultdict(int)
connection_tracking = {}
traffic_by_ip = defaultdict(int)
http_requests = []


# Helper functions
def get_available_interfaces():
    """Get a list of available network interfaces."""
    interfaces = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip != "0.0.0.0":
                interfaces.append({
                    'name': iface,
                    'ip': ip,
                    'mac': netifaces.ifaddresses(iface).get(netifaces.AF_LINK, [{'addr': None}])[0]['addr'],
                    'type': 'Wireless' if 'wlan' in iface or 'wifi' in iface else 'Ethernet'
                })
        except:
            continue
    return interfaces


def detect_packet_type(packet):
    """Identify packet type and extract relevant information."""
    packet_info = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
        'size': len(packet),
        'protocol': 'Unknown'
    }

    # Layer 2 analysis
    if Ether in packet:
        packet_info['src_mac'] = packet[Ether].src
        packet_info['dst_mac'] = packet[Ether].dst
        packet_info['l2_type'] = 'Ethernet'
    elif Dot11 in packet:
        packet_info['src_mac'] = packet[Dot11].addr2
        packet_info['dst_mac'] = packet[Dot11].addr1
        packet_info['l2_type'] = 'WiFi'

    # Layer 3 analysis
    if IP in packet:
        packet_info['src_ip'] = packet[IP].src
        packet_info['dst_ip'] = packet[IP].dst
        packet_info['ttl'] = packet[IP].ttl
        packet_info['l3_protocol'] = 'IPv4'
    
    # Layer 4 analysis and protocol identification
    if TCP in packet:
        packet_info['protocol'] = 'TCP'
        packet_info['src_port'] = packet[TCP].sport
        packet_info['dst_port'] = packet[TCP].dport
        packet_info['flags'] = parse_tcp_flags(packet[TCP].flags)
        packet_info['seq'] = packet[TCP].seq
        packet_info['ack'] = packet[TCP].ack
        
        # Identify application layer protocols
        if packet_info['dst_port'] == 80 or packet_info['src_port'] == 80:
            packet_info['protocol'] = 'HTTP'
            extract_http_info(packet, packet_info)
        elif packet_info['dst_port'] == 443 or packet_info['src_port'] == 443:
            packet_info['protocol'] = 'HTTPS'
        elif packet_info['dst_port'] == 22 or packet_info['src_port'] == 22:
            packet_info['protocol'] = 'SSH'
        elif packet_info['dst_port'] == 21 or packet_info['src_port'] == 21:
            packet_info['protocol'] = 'FTP'
        
    elif UDP in packet:
        packet_info['protocol'] = 'UDP'
        packet_info['src_port'] = packet[UDP].sport
        packet_info['dst_port'] = packet[UDP].dport
        
        # Identify application layer protocols
        if packet_info['dst_port'] == 53 or packet_info['src_port'] == 53:
            packet_info['protocol'] = 'DNS'
            if DNS in packet:
                extract_dns_info(packet, packet_info)
        elif packet_info['dst_port'] == 123 or packet_info['src_port'] == 123:
            packet_info['protocol'] = 'NTP'
        elif packet_info['dst_port'] == 67 or packet_info['dst_port'] == 68:
            packet_info['protocol'] = 'DHCP'
            
    elif ICMP in packet:
        packet_info['protocol'] = 'ICMP'
        packet_info['type'] = packet[ICMP].type
        packet_info['code'] = packet[ICMP].code
        
    elif ARP in packet:
        packet_info['protocol'] = 'ARP'
        packet_info['operation'] = 'Request' if packet[ARP].op == 1 else 'Reply'
        packet_info['src_ip'] = packet[ARP].psrc
        packet_info['dst_ip'] = packet[ARP].pdst
        
    return packet_info


def parse_tcp_flags(flags):
    """Convert TCP flags value to human-readable format."""
    flag_meanings = {
        'F': 'FIN',
        'S': 'SYN',
        'R': 'RST',
        'P': 'PSH',
        'A': 'ACK',
        'U': 'URG',
        'E': 'ECE',
        'C': 'CWR'
    }
    
    flag_chars = str(flags)
    return [flag_meanings.get(f, f) for f in flag_chars if f in flag_meanings]


def extract_http_info(packet, packet_info):
    """Extract HTTP information from packet."""
    if Raw in packet:
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Check for HTTP request
            if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                lines = payload.split('\r\n')
                request_line = lines[0]
                packet_info['http_method'] = request_line.split()[0]
                packet_info['http_uri'] = request_line.split()[1]
                
                # Extract host if available
                for line in lines[1:]:
                    if line.lower().startswith('host:'):
                        packet_info['http_host'] = line.split(':', 1)[1].strip()
                        break
                        
            # Check for HTTP response
            elif payload.startswith('HTTP/'):
                lines = payload.split('\r\n')
                status_line = lines[0]
                parts = status_line.split()
                if len(parts) >= 2:
                    packet_info['http_status'] = parts[1]
                
        except Exception:
            # Malformed or binary HTTP data
            pass


def extract_dns_info(packet, packet_info):
    """Extract DNS information from packet."""
    if DNS in packet:
        dns = packet[DNS]
        packet_info['dns_id'] = dns.id
        
        if dns.qr == 0:
            # DNS query
            packet_info['dns_type'] = 'Query'
            if dns.qd and dns.qd.qname:
                packet_info['dns_query'] = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
        else:
            # DNS response
            packet_info['dns_type'] = 'Response'
            if dns.qd and dns.qd.qname:
                packet_info['dns_query'] = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            
            # Extract answers
            answers = []
            for i in range(dns.ancount):
                try:
                    dnsrr = dns.an[i]
                    if hasattr(dnsrr, 'rdata'):
                        if isinstance(dnsrr.rdata, bytes):
                            answers.append(dnsrr.rdata.decode('utf-8', errors='ignore'))
                        else:
                            answers.append(str(dnsrr.rdata))
                except Exception:
                    pass
            
            if answers:
                packet_info['dns_answers'] = answers


def packet_handler(packet):
    """Handler for each captured packet."""
    if not running.value:
        return

    try:
        # Update statistics
        statistics['packet_count'].value += 1
        statistics['bytes_captured'].value += len(packet)
        
        # Extract packet information
        packet_info = detect_packet_type(packet)
        
        # Put packet info in the queue for processing by the analysis process
        packet_queue.put(packet_info)
        
    except Exception as e:
        print(f"Error processing packet: {e}")


def packet_capture_process(interface, bpf_filter):
    """Process for capturing packets."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # Ignore Ctrl+C in this process
    
    print(f"Starting packet capture on interface: {interface}")
    print(f"Using filter: {bpf_filter if bpf_filter else 'None'}")
    
    try:
        sniff(
            iface=interface,
            prn=packet_handler,
            filter=bpf_filter,
            store=0
        )
    except Exception as e:
        print(f"Error in packet capture: {e}")
    
    print("Packet capture stopped")


def packet_analysis_process():
    """Process for analyzing packets and sending to frontend."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # Ignore Ctrl+C in this process
    
    print("Starting packet analysis process")
    
    # Initialize counters
    protocol_stats = defaultdict(int)
    ip_stats = defaultdict(int)
    http_stats = []
    dns_stats = []
    connections = {}
    
    last_emit_time = time.time()
    emit_interval = 0.25  # Send updates to frontend every 250ms
    
    try:
        while running.value or not packet_queue.empty():
            try:
                # Non-blocking queue get with timeout
                packet_info = packet_queue.get(timeout=0.1)
                
                # Update protocol statistics
                protocol = packet_info.get('protocol', 'Unknown')
                protocol_stats[protocol] += 1
                
                # Update IP statistics
                if 'src_ip' in packet_info:
                    ip_stats[packet_info['src_ip']] += packet_info['size']
                if 'dst_ip' in packet_info:
                    ip_stats[packet_info['dst_ip']] += packet_info['size']
                
                # Track connections
                if 'src_ip' in packet_info and 'dst_ip' in packet_info and 'protocol' in packet_info:
                    if protocol in ('TCP', 'UDP'):
                        conn_id = f"{packet_info['src_ip']}:{packet_info.get('src_port', '?')}-" \
                                f"{packet_info['dst_ip']}:{packet_info.get('dst_port', '?')}"
                        
                        if conn_id not in connections:
                            connections[conn_id] = {
                                'src_ip': packet_info['src_ip'],
                                'dst_ip': packet_info['dst_ip'],
                                'src_port': packet_info.get('src_port', '?'),
                                'dst_port': packet_info.get('dst_port', '?'),
                                'protocol': protocol,
                                'packets': 0,
                                'bytes': 0,
                                'start_time': time.time()
                            }
                        
                        connections[conn_id]['packets'] += 1
                        connections[conn_id]['bytes'] += packet_info['size']
                        connections[conn_id]['last_seen'] = time.time()
                
                # Collect HTTP data
                if protocol == 'HTTP' and 'http_method' in packet_info:
                    http_stats.append({
                        'timestamp': packet_info['timestamp'],
                        'method': packet_info['http_method'],
                        'uri': packet_info.get('http_uri', ''),
                        'host': packet_info.get('http_host', '')
                    })
                    
                    # Keep only the last 100 HTTP requests
                    if len(http_stats) > 100:
                        http_stats.pop(0)
                
                # Collect DNS data
                if protocol == 'DNS' and 'dns_query' in packet_info:
                    dns_stats.append({
                        'timestamp': packet_info['timestamp'],
                        'query': packet_info['dns_query'],
                        'type': packet_info.get('dns_type', ''),
                        'answers': packet_info.get('dns_answers', [])
                    })
                    
                    # Keep only the last 100 DNS queries
                    if len(dns_stats) > 100:
                        dns_stats.pop(0)
                
                # Emit to frontend periodically rather than for every packet
                current_time = time.time()
                if current_time - last_emit_time >= emit_interval:
                    # Get system stats
                    net_io = psutil.net_io_counters()
                    
                    # Prepare stats for frontend
                    stats = {
                        'packet_count': statistics['packet_count'].value,
                        'bytes_captured': statistics['bytes_captured'].value,
                        'duration': current_time - statistics['start_time'],
                        'protocol_stats': dict(protocol_stats),
                        'top_talkers': dict(sorted(ip_stats.items(), key=lambda x: x[1], reverse=True)[:10]),
                        'connections': list(connections.values()),
                        'http_requests': http_stats,
                        'dns_queries': dns_stats,
                        'system_stats': {
                            'bytes_sent': net_io.bytes_sent,
                            'bytes_recv': net_io.bytes_recv,
                            'packets_sent': net_io.packets_sent,
                            'packets_recv': net_io.packets_recv,
                            'cpu_percent': psutil.cpu_percent(),
                            'memory_percent': psutil.virtual_memory().percent
                        }
                    }
                    
                    # Send latest packet and stats to frontend
                    socketio.emit('packet_captured', packet_info)
                    socketio.emit('stats_update', stats)
                    
                    last_emit_time = current_time
                    
            except multiprocessing.queues.Empty:
                # No packets in queue, check if we should emit stats anyway
                current_time = time.time()
                if current_time - last_emit_time >= 1.0:  # At least update stats every second
                    socketio.emit('stats_update', {
                        'packet_count': statistics['packet_count'].value,
                        'bytes_captured': statistics['bytes_captured'].value,
                        'duration': current_time - statistics['start_time'],
                        'protocol_stats': dict(protocol_stats),
                        'connections': list(connections.values())
                    })
                    last_emit_time = current_time
                
    except Exception as e:
        print(f"Error in packet analysis: {e}")
        
    print("Packet analysis stopped")


# Flask routes
@app.route('/')
def index():
    """Serve the main application interface."""
    interfaces = get_available_interfaces()
    return render_template('index.html', interfaces=interfaces)


@app.route('/templates/index.html')
def get_template():
    """Serve the HTML template."""
    interfaces = get_available_interfaces()
    return render_template('index.html', interfaces=interfaces)


# Socket.IO events
@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    print(f"Client connected: {request.sid}")
    socketio.emit('interfaces', get_available_interfaces())


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    print(f"Client disconnected: {request.sid}")


@socketio.on('start_capture')
def handle_start_capture(data):
    """Start packet capture with given parameters."""
    global running
    
    interface = data.get('interface')
    bpf_filter = data.get('filter', '')
    
    if not interface:
        return {'success': False, 'error': 'No interface specified'}
    
    # Reset statistics
    statistics['packet_count'].value = 0
    statistics['bytes_captured'].value = 0
    statistics['start_time'] = time.time()
    
    # Set running flag
    running.value = True
    
    # Start capture process
    capture_proc = multiprocessing.Process(
        target=packet_capture_process,
        args=(interface, bpf_filter)
    )
    capture_proc.daemon = True
    capture_proc.start()
    
    # Start analysis process if it's not already running
    analysis_proc = multiprocessing.Process(
        target=packet_analysis_process
    )
    analysis_proc.daemon = True
    analysis_proc.start()
    
    socketio.emit('capture_started', {
        'interface': interface,
        'filter': bpf_filter,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    
    return {'success': True}


@socketio.on('stop_capture')
def handle_stop_capture():
    """Stop packet capture."""
    global running
    running.value = False
    
    socketio.emit('capture_stopped', {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    
    return {'success': True}


@socketio.on('get_interfaces')
def handle_get_interfaces():
    """Get available network interfaces."""
    interfaces = get_available_interfaces()
    return {'interfaces': interfaces}

