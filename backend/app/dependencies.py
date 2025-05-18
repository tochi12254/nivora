# dependencies.py
from services.prevention.firewall import PyFirewall
from fastapi import Depends

_firewall_instance = None


async def get_firewall():
    global _firewall_instance
    if _firewall_instance is None:
        _firewall_instance = PyFirewall()
        await _firewall_instance.initialize()
    return _firewall_instance
