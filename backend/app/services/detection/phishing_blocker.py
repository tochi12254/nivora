import json
from typing import Dict, List
import multiprocessing
import time
from datetime import datetime
from urllib.parse import urlparse
import tldextract
import re
import logging
from socketio import Client
from .phishing_detector import ClassicalPhishingDetector


logger = logging.getLogger(__name__)

class PhishingBlocker:
    def __init__(self, sio: Client):
        self.sio = sio
        self.detector = ClassicalPhishingDetector()
        self.blocked_domains = set()
        self.blocked_ips = set()
        self.running = multiprocessing.Value("b", True)

        # Start detector in live mode
        self.detector.start()

        # Start background processors
        self.result_processor = multiprocessing.Process(
            target=self.process_detection_results
        )
        self.result_processor.start()

        # Register socket.io events
        self.register_socket_handlers()

    def register_socket_handlers(self):
        """Register socket.io event handlers"""

        @self.sio.on("manual_phishing_check")
        async def handle_manual_check(data):
            result = self.manual_check(data["url"])
            await self.sio.emit("phishing_check_result", result)

        @self.sio.on("get_blocked_domains")
        async def handle_get_blocked():
            await self.sio.emit(
                "blocked_domains_list",
                {"domains": list(self.blocked_domains), "ips": list(self.blocked_ips)},
            )

    async def send_alert(self, alert_data: Dict):
        """Send alert to all connected clients"""
        await self.sio.emit("phishing_alert", alert_data)

    async def send_block_notification(self, domain: str, ip: str = None):
        """Notify clients about blocked resource"""
        await self.sio.emit(
            "resource_blocked",
            {"domain": domain, "ip": ip, "timestamp": datetime.utcnow().isoformat()},
        )

    def process_http_activity(self, http_data: Dict):
        """Process HTTP activity from packet sniffer"""
        url = f"https://{http_data['host']}{http_data.get('path', '')}"

        # Check if already blocked
        domain = urlparse(url).netloc.split(":")[0]
        if domain in self.blocked_domains or http_data["source_ip"] in self.blocked_ips:
            self.sio.start_background_task(
                self.send_block_notification, domain=domain, ip=http_data["source_ip"]
            )
            return {"action": "blocked", "reason": "previously blocked"}

        # Analyze for phishing
        self.detector.live_monitor(
            {"http": {"host": http_data["host"], "path": http_data.get("path", "")}}
        )

    async def process_detection_results(self):
        """Background process to handle detection results"""
        while self.running.value:
            try:
                if not self.detector.result_queue.empty():
                    alert = self.detector.result_queue.get()

                    # Extract domain from URL
                    domain = urlparse(alert["url"]).netloc.split(":")[0]

                    # Add to block lists
                    self.blocked_domains.add(domain)

                    # Send real-time alert
                    alert_data = {
                        **alert,
                        "action_taken": "blocked",
                        "blocked_domain": domain,
                    }
                    self.sio.start_background_task(self.send_alert, alert_data)

                    # Log the block action
                    logger.info(f"🚫 Blocked phishing attempt: {alert['url']}")
                    await self.sio.emit(
                        "blocked_phishing_attempt",
                        {
                            "url": alert["url"]
                        },
                    )

            except Exception as e:
                print(f"Error processing detection results: {e}")
            time.sleep(0.1)

    def manual_check(self, url: str) -> Dict:
        """Manual phishing check endpoint"""
        result = self.detector.manual_check(url)

        # If phishing, add to block list immediately
        if result.is_phishing:
            domain = urlparse(url).netloc.split(":")[0]
            self.blocked_domains.add(domain)
            self.sio.start_background_task(self.send_block_notification, domain=domain)

        return {
            "url": result.url,
            "is_phishing": result.is_phishing,
            "risk_score": result.risk_score,
            "reasons": result.reasons,
            "blocked": result.is_phishing,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def is_blocked(self, host: str, ip: str) -> bool:
        """Check if domain or IP is blocked"""
        return host in self.blocked_domains or ip in self.blocked_ips

    def stop(self):
        """Clean shutdown"""
        self.running.value = False
        self.detector.stop()
        self.result_processor.join()
