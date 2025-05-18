# backend/app/services/siem_integration.py
import aiohttp
import json
import logging
from datetime import datetime
from typing import Dict, Optional
import ssl
import certifi

logger = logging.getLogger("siem")


class SIEMForwarder:
    FORMATS = {"cef": self._format_cef, "leef": self._format_leef, "json": lambda x: x}

    def __init__(self, config: Dict):
        self.config = config
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        self.session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=self.ssl_context)
        )

    async def forward_event(self, event: Dict, format_type: str = "cef") -> bool:
        """Forward event to SIEM in specified format"""
        formatter = self.FORMATS.get(format_type.lower())
        if not formatter:
            raise ValueError(f"Unsupported format: {format_type}")

        formatted = formatter(event)
        endpoint = self.config["endpoints"].get(format_type)

        try:
            async with self.session.post(
                endpoint["url"],
                data=formatted,
                headers=endpoint.get("headers", {}),
                timeout=aiohttp.ClientTimeout(total=5),
            ) as response:
                if response.status >= 400:
                    logger.error(
                        f"SIEM rejected event: {response.status} {await response.text()}"
                    )
                    return False
                return True
        except Exception as e:
            logger.error(f"SIEM forwarding error: {str(e)}")
            return False

    def _format_cef(self, event: Dict) -> str:
        """Format event as CEF"""
        extensions = {
            "src": event.get("source_ip"),
            "dst": event.get("dest_ip"),
            "act": event.get("action"),
            "msg": event.get("message"),
            "cs1": json.dumps(event.get("mitre_techniques", [])),
            "cs1Label": "MITRE Techniques",
        }

        extensions_str = " ".join(
            f"{k}={self._cef_escape(str(v))}"
            for k, v in extensions.items()
            if v is not None
        )

        return (
            f"CEF:0|CyberWatch|Security|1.0|{event.get('event_code', 0)}|"
            f"{event.get('event_name', 'Unknown')}|{event.get('severity', 5)}|{extensions_str}"
        )

    async def batch_forward(self, events: List[Dict], batch_size: int = 100) -> Dict:
        """Forward events in batches with failover"""
        results = {"success": 0, "failed": 0, "errors": []}

        for i in range(0, len(events), batch_size):
            batch = events[i : i + batch_size]
            try:
                if await self.forward_event({"batch": batch}, "json"):
                    results["success"] += len(batch)
                else:
                    results["failed"] += len(batch)
            except Exception as e:
                results["failed"] += len(batch)
                results["errors"].append(str(e))

        return results

    async def health_check(self) -> bool:
        """Verify SIEM connectivity"""
        try:
            async with self.session.get(
                f"{self.config['endpoints']['json']['url']}/health", timeout=2
            ) as response:
                return response.status == 200
        except Exception:
            return False

    def _cef_escape(self, value: str) -> str:
        """Escape special characters for CEF"""
        return value.translate(
            str.maketrans(
                {"\\": r"\\", "|": r"\|", "=": r"\=", "\n": r"\n", "\r": r"\r"}
            )
        )
