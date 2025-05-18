import re
import logging
from typing import List

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("IPS")

class IntrusionPreventionSystem:
    def __init__(self):
        self.blocked_ips = set()
        self.rules = []

    def add_rule(self, pattern: str):
        """Add a regex pattern to detect malicious activity."""
        try:
            compiled_pattern = re.compile(pattern)
            self.rules.append(compiled_pattern)
            logger.info(f"Rule added: {pattern}")
        except re.error as e:
            logger.error(f"Invalid regex pattern: {pattern}. Error: {e}")

    def analyze_traffic(self, ip: str, data: str) -> bool:
        """
        Analyze incoming traffic and block IP if malicious activity is detected.
        Returns True if the IP is blocked, False otherwise.
        """
        if ip in self.blocked_ips:
            logger.warning(f"Traffic from blocked IP {ip} detected. Dropping connection.")
            return True

        for rule in self.rules:
            if rule.search(data):
                logger.warning(f"Malicious activity detected from IP {ip}. Blocking IP.")
                self.blocked_ips.add(ip)
                return True

        logger.info(f"Traffic from IP {ip} is clean.")
        return False

    def unblock_ip(self, ip: str):
        """Unblock a previously blocked IP."""
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            logger.info(f"IP {ip} has been unblocked.")
        else:
            logger.info(f"IP {ip} is not in the blocked list.")

    def get_blocked_ips(self) -> List[str]:
        """Return a list of currently blocked IPs."""
        return list(self.blocked_ips)


# Example usage
if __name__ == "__main__":
    ips = IntrusionPreventionSystem()

    # Add rules to detect malicious patterns
    ips.add_rule(r"SELECT \* FROM")  # Example SQL injection pattern
    ips.add_rule(r"(\.\./)+")       # Directory traversal pattern

    # Simulate traffic
    traffic_samples = [
        ("192.168.1.1", "Normal traffic data"),
        ("192.168.1.2", "SELECT * FROM users WHERE id=1"),
        ("192.168.1.3", "../../etc/passwd"),
    ]

    for ip, data in traffic_samples:
        ips.analyze_traffic(ip, data)

    # Check blocked IPs
    logger.info(f"Blocked IPs: {ips.get_blocked_ips()}")