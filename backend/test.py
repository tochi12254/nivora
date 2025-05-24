import psutil
import socket

for interface, addrs in psutil.net_if_addrs().items():
    print(f"Interface: {interface}")
    for addr in addrs:
        if addr.family == socket.AF_INET:
            print(f"  → IP: {addr.address}")
