import re
from typing import List, Dict, Optional
import yaml
from pathlib import Path
import logging
from dataclasses import dataclass
from scapy.all import Packet

logger = logging.getLogger(__name__)


@dataclass
class SignatureRule:
    id: str
    name: str
    protocol: str
    pattern: str
    action: str
    severity: str
    description: str
    compiled_pattern: re.Pattern = None

    def __post_init__(self):
        try:
            self.compiled_pattern = re.compile(self.pattern, re.IGNORECASE)
        except re.error as e:
            logger.error(f"Invalid regex pattern in rule {self.id}: {self.pattern}")
            raise


class SignatureEngine:
    def __init__(self, rule_files: List[str] = None):
        self.rules: List[SignatureRule] = []
        self.protocol_handlers = {
            "http": self._match_http,
            "dns": self._match_dns,
            "tcp": self._match_tcp,
            "udp": self._match_udp,
            "icmp": self._match_icmp,
            "ip": self._match_ip,
        }

        if rule_files:
            self.load_rules(rule_files)
        else:
            self.load_default_rules()

    def load_default_rules(self):
        """Load built-in default rules"""
        default_rules = [
            {
                "id": "http-sqli-1",
                "name": "SQL Injection Attempt",
                "protocol": "http",
                "pattern": r"(union\s+select|1=1|sleep\(\d+\)|or\s+1=1)",
                "action": "alert",
                "severity": "high",
                "description": "Detects common SQL injection patterns in HTTP requests",
            },
            {
                "id": "http-xss-1",
                "name": "Cross-Site Scripting (XSS) Attempt",
                "protocol": "http",
                "pattern": r"(<script>|javascript:|onerror=|onload=)",
                "action": "alert",
                "severity": "medium",
                "description": "Detects possible XSS attack vectors in web traffic",
            },
            {
                "id": "http-rce-1",
                "name": "Remote Command Execution Attempt",
                "protocol": "http",
                "pattern": r"(;|&&|\|\||`|base64\s+-d|bash\s+-c)",
                "action": "alert",
                "severity": "critical",
                "description": "Detects possible RCE payloads in web requests",
            },
            {
                "id": "dns-exfil-1",
                "name": "DNS Exfiltration Attempt",
                "protocol": "dns",
                "pattern": r"([a-z0-9]{20,}\.(exfil|data|steal)\.(com|net|org))",
                "action": "alert",
                "severity": "critical",
                "description": "Detects potential data exfiltration via DNS tunneling",
            },
            {
                "id": "ssh-brute-1",
                "name": "SSH Brute Force",
                "protocol": "ssh",
                "pattern": r"(Failed password for.*from)",
                "action": "alert",
                "severity": "high",
                "description": "Detects brute force attempts against SSH",
            },
            {
                "id": "ftp-login-1",
                "name": "FTP Anonymous Login",
                "protocol": "ftp",
                "pattern": r"(USER anonymous)",
                "action": "alert",
                "severity": "medium",
                "description": "Detects anonymous FTP login attempt",
            },
            {
                "id": "smtp-phish-1",
                "name": "SMTP Phishing Attempt",
                "protocol": "smtp",
                "pattern": r"(Subject:.*(urgent|verify|account|password))",
                "action": "alert",
                "severity": "high",
                "description": "Detects phishing attempt via email",
            },
            {
                "id": "scan-nmap-1",
                "name": "Nmap Port Scan",
                "protocol": "any",
                "pattern": r"(Nmap scan report for)",
                "action": "alert",
                "severity": "low",
                "description": "Detects basic port scanning activity",
            },
            {
                "id": "malware-c2-1",
                "name": "Malware C2 Beaconing",
                "protocol": "http",
                "pattern": r"(\/gate\.php|\/connect\.php|\/api\/v1\/report)",
                "action": "alert",
                "severity": "critical",
                "description": "Detects common malware command-and-control beacon paths",
            },
            {
                "id": "smb-exploit-1",
                "name": "SMB Exploit Attempt",
                "protocol": "smb",
                "pattern": r"(\\x90\\x90\\x90|EternalBlue|MS17-010)",
                "action": "alert",
                "severity": "critical",
                "description": "Detects possible SMB exploitation attempts",
            },
            {
                "id": "generic-dos-1",
                "name": "Possible DoS Attempt",
                "protocol": "any",
                "pattern": r"(SYN\s+flood|ICMP\s+flood)",
                "action": "alert",
                "severity": "high",
                "description": "Detects denial-of-service patterns",
            },
            {
                "id": "ransomware-indicator-1",
                "name": "Ransomware File Access Pattern",
                "protocol": "filesystem",
                "pattern": r"(\.encrypted|\.locked|\.crypto|\.crypt)",
                "action": "alert",
                "severity": "critical",
                "description": "Detects access to known ransomware-encrypted files",
            },
        ]


        for rule in default_rules:
            try:
                self.rules.append(SignatureRule(**rule))
            except Exception as e:
                logger.error(f"Failed to load rule {rule.get('id')}: {str(e)}")

    def load_rules(self, rule_files: List[str]):
        """Load rules from YAML files"""
        for rule_file in rule_files:
            try:
                with open(rule_file, "r") as f:
                    rules_data = yaml.safe_load(f)

                    for rule in rules_data.get("rules", []):
                        try:
                            self.rules.append(SignatureRule(**rule))
                        except Exception as e:
                            logger.error(f"Invalid rule in {rule_file}: {str(e)}")

            except Exception as e:
                logger.error(f"Failed to load rule file {rule_file}: {str(e)}")

    def detect(self, packet: Packet) -> Optional[Dict]:
        """Detect threats in packet based on signatures"""
        for rule in self.rules:
            try:
                handler = self.protocol_handlers.get(rule.protocol)
                if handler and handler(packet, rule):
                    return {
                        "rule_id": rule.id,
                        "threat_name": rule.name,
                        "severity": rule.severity,
                        "description": rule.description,
                        "packet_summary": packet.summary(),
                    }
            except Exception as e:
                logger.error(f"Error processing rule {rule.id}: {str(e)}")
        return None

    def _match_http(self, packet: Packet, rule: SignatureRule) -> bool:
        """Match HTTP packets against rules"""
        if not packet.haslayer("HTTP"):
            return False

        payload = bytes(packet["TCP"].payload)
        return bool(rule.compiled_pattern.search(payload.decode("latin-1")))

    def _match_dns(self, packet: Packet, rule: SignatureRule) -> bool:
        """Match DNS packets against rules"""
        if not packet.haslayer("DNS"):
            return False

        dns = packet["DNS"]
        if dns.qr == 0:  # Query
            query = dns.qd.qname.decode("latin-1") if dns.qd else ""
            return bool(rule.compiled_pattern.search(query))
        else:  # Response
            for i in range(dns.ancount):
                answer = (
                    dns.an[i].rdata.decode("latin-1")
                    if hasattr(dns.an[i], "rdata")
                    else ""
                )
                if rule.compiled_pattern.search(answer):
                    return True
        return False

    def _match_tcp(self, packet: Packet, rule: SignatureRule) -> bool:
        """Match TCP packets against rules"""
        if not packet.haslayer("TCP"):
            return False

        payload = bytes(packet["TCP"].payload)
        return bool(rule.compiled_pattern.search(payload.decode("latin-1")))

    def _match_udp(self, packet: Packet, rule: SignatureRule) -> bool:
        """Match UDP packets against rules"""
        if not packet.haslayer("UDP"):
            return False

        payload = bytes(packet["UDP"].payload)
        return bool(rule.compiled_pattern.search(payload.decode("latin-1")))

    def _match_icmp(self, packet: Packet, rule: SignatureRule) -> bool:
        """Match ICMP packets against rules"""
        if not packet.haslayer("ICMP"):
            return False

        payload = bytes(packet["ICMP"].payload)
        return bool(rule.compiled_pattern.search(payload.decode("latin-1")))

    def _match_ip(self, packet: Packet, rule: SignatureRule) -> bool:
        """Match IP packets against rules"""
        if not packet.haslayer("IP"):
            return False

        payload = bytes(packet["IP"].payload)
        return bool(rule.compiled_pattern.search(payload.decode("latin-1")))

    def add_rule(self, rule: Dict):
        """Add a new rule at runtime"""
        try:
            self.rules.append(SignatureRule(**rule))
            return True
        except Exception as e:
            logger.error(f"Failed to add rule: {str(e)}")
            return False

    def get_rules(self) -> List[Dict]:
        """Get all current rules"""
        return [
            {
                "id": rule.id,
                "name": rule.name,
                "protocol": rule.protocol,
                "severity": rule.severity,
                "description": rule.description,
            }
            for rule in self.rules
        ]
