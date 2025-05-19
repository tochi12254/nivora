
def _analyze_http(self, packet: Packet):
    """Comprehensive HTTP analysis with advanced threat detection"""
    http_layer = None
    if packet.haslayer(HTTPRequest):
        http_layer = packet[HTTPRequest]
    elif packet.haslayer(HTTPResponse):
        http_layer = packet[HTTPResponse]

    if not http_layer:
        return

    # Payload extraction with chunked encoding support
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
        "observability_metrics": {},
    }
    
    flow_info = {}
    try:
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
            
    ip_layer = packet[IP] if packet.haslayer(IP) else None
    header_fields = http_layer.fields if http_layer else {}
    header_length = sum(len(str(k)) + len(str(v)) for k, v in header_fields.items())

    http_data.update(
        {
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
                "payload_characteristics": {
                    "entropy": self._calculate_entropy(payload),
                    "hex_patterns": self._find_hex_patterns(payload),
                    "header_length": header_length,
                    "compression_ratio": len(payload) / (header_length + 1) if payload else 0,
                    "header_field_count": len(header_fields),
                    "content_gap_analysis": self._analyze_content_gaps(payload),
                    "protocol_specific": {
                        "http_version": http_layer.Http_Version if hasattr(http_layer, "Http_Version") else None,
                        "status_code": http_layer.Status_Code if hasattr(http_layer, "Status_Code") else None,
                    },
                    "printable_ratio": sum(32 <= c < 127 for c in payload) / len(payload) if payload else 0,
                },
            },
            "session_context": {
                "request_count": self._get_session_count(packet[IP].src) if packet.haslayer(IP) else 0,
                "unique_endpoints": self._get_unique_endpoints(packet[IP].src) if packet.haslayer(IP) else 0,
                "flow_duration": round(flow_duration, 4),
                "flow_id": hash(flow_key) if flow_key else None,
                "direction": flow_info.get("direction", "unknown"),
                "session_state": "new" if flow_info.get("packet_count", 0) == 1 else "established"
            },
        }
    )
    
    try:
        self._update_traffic_baseline(http_data)
        http_data.update({
            "compliance_checks": {
                "rfc_compliance": self._check_rfc_compliance(http_layer),
                "tls_version": self.__parse_tls_version_from_bytes(packet),
                "ciphersuite_analysis": self._analyze_ciphersuites(packet),
            },
            "observability_metrics": {
                "hop_count": 255 - http_data["network_metrics"].get("ttl", 0) 
                            if http_data["network_metrics"].get("ttl") else None,
                "path_analysis": self._analyze_network_path(http_data["source_ip"]),
                "asn_info": self._get_asn_info(http_data["source_ip"]),
            }})
        
    except Exception as e:
        logger.warning(f"Error: { str(e)}")

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
        "data_exfiltration": self._detect_payload_exfiltration(payload),
        "path_exfiltration": self._detect_path_exfiltration(http_data["path"]),
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
        self.sio_queue.put(
            (
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
            self.sio_queue.put_nowait(
                ("signature_match", {**sig_results, "context": http_data})
            )

    self.sio_queue.put(("http_activity", http_data))