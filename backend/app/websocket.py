def _analyze_dns(self, packet: Packet):
        """Enhanced DNS analysis with TTL monitoring and protocol safety"""
        try:

            if not (packet.haslayer(DNS) and packet.haslayer(IP)):
                logger.debug("Invalid DNS packet structure")
                return

            dns = packet[DNS]
            ip = packet[IP]
            queries = []
            responses = []

            # Process DNS queries with enhanced safety
            if dns.qd:
                for question in dns.qd:
                    try:
                        raw_name = self._safe_extract(question, "qname", decode=False)
                        decoded_name = self._sanitize_dns_query(raw_name)
                        queries.append({
                            "name": decoded_name,
                            "type": self._safe_extract(question, "qtype"),
                            "class": self._safe_extract(question, "qclass")
                        })
                    except Exception as qe:
                        logger.warning("DNS query processing error: %s", str(qe))

            # Process DNS responses with full error isolation
            if dns.an:
                for answer in dns.an:
                    try:
                        response = {
                            "name": self._sanitize_dns_query(
                                self._safe_extract(answer, "rrname", decode=False)
                            ),
                            "type": self._safe_extract(answer, "type"),
                            "ttl": int(self._safe_extract(answer, "ttl", 0)),
                            "data": self._sanitize_dns_query(
                                self._safe_extract(answer, "rdata", "")
                            ) if hasattr(answer, "rdata") else None,
                            "class": self._safe_extract(answer, "rclass")
                        }
                        responses.append(response)
                    except Exception as ae:
                        logger.warning("DNS answer processing error: %s", str(ae))

            # Build DNS data structure with fallback values
            dns_data = {
                "timestamp": datetime.utcnow().isoformat(),
                "source_ip": self._safe_extract(ip, "src"),
                "destination_ip": self._safe_extract(ip, "dst"),
                "protocol": "udp" if packet.haslayer(UDP) else "tcp",
                "query_count": len(queries),
                "response_count": len(responses),
                "opcode": self._safe_extract(dns, "opcode"),
                "rcode": self._safe_extract(dns, "rcode"),
                "queries": queries,
                "responses": responses,
                "is_suspicious": any(
                    str(q.get("type", "")).strip() in {"12", "16", "PTR", "TXT"} 
                    for q in queries
                ),
                "tunnel_analysis": {
                    "likely_tunnel": bool(self._detect_dns_tunneling(queries, responses)),
                    "dga_score": float(self._calculate_dga_score(queries)),
                },
                "correlation_features": {
                    "query_chain_depth": len([
                        rr for rr in responses 
                        if str(rr.get("type", "")).strip() in {"5", "CNAME"}
                    ]),
                    "nxdomain_ratio": float(self._get_nxdomain_ratio(queries)),
                    "ttl_variation": self.safe_float(np.std(
                        [r.get("ttl", 0) for r in responses]
                    )) if responses else 0.0,
                    "subdomain_entropy": float(
                        self._calculate_subdomain_entropy(queries)
                    ),
                },
                "nxdomain_ratio": float(self._get_nxdomain_ratio(queries)),
                "unique_domains": len({
                    q["name"] for q in queries 
                    if q.get("name") and isinstance(q["name"], str)
                }),
            }

            # TTL anomaly detection with safety
            if responses:
                try:
                    avg_ttl = sum(r.get("ttl", 0) for r in responses) / len(responses)
                    dns_data["ttl_anomaly"] = bool(avg_ttl < 30)
                    dns_data["average_ttl"] = round(avg_ttl, 2)
                except ZeroDivisionError:
                    dns_data["ttl_anomaly"] = False
                    dns_data["average_ttl"] = 0.0

            # Queue handling with multiple safety layers
            try:
                self.sio_queue.put_nowait(("dns_activity", dns_data))
                logger.info("DNS analysis completed successfully")
            except Full:
                logger.warning("DNS queue capacity exceeded, dropping packet")

            except Exception as qe:
                logger.error("DNS queue submission failed: %s", str(qe))
