# scripts/test_malware.py
import requests
from scapy.all import sniff, IP, TCP
from services.prevention.firewall import FirewallManager

MALWARE_IPS = ["185.130.5.253", "91.219.236.222"]  # Known malicious IPs
firewall = FirewallManager()


def analyze_malware_traffic(pkt):
    if IP in pkt and pkt[IP].src in MALWARE_IPS:
        print(f"Malware traffic detected from {pkt[IP].src}")
        firewall.block_ip(pkt[IP].src, "Known malware IP")


# Start sniffing
sniff(prn=analyze_malware_traffic, filter="ip", store=False)
