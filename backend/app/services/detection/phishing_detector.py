import re
import multiprocessing
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Set, Optional
import time
import tldextract
from dataclasses import dataclass
import json
from datetime import datetime


@dataclass
class PhishingResult:
    url: str
    is_phishing: bool
    risk_score: float  # 0.0 to 1.0
    reasons: List[str]
    timestamp: str


class ClassicalPhishingDetector:
    def __init__(self):
        # Initialize detection databases
        self.trusted_domains = {
            "paypal.com",
            "google.com",
            "microsoft.com",
            "apple.com",
            "amazon.com",
            "linkedin.com",
            "facebook.com",
            "dropbox.com",
            "github.com",
            "bankofamerica.com",
            "icloud.com",
            "outlook.com",
            "chase.com",
            "twitter.com",
            "instagram.com",
            "yahoo.com",
            "citibank.com",
            "wellsfargo.com",
        }

        self.suspicious_keywords = {
            "login",
            "verify",
            "account",
            "secure",
            "banking",
            "update",
            "confirm",
            "signin",
            "submit",
            "reset",
            "payment",
            "security",
            "alert",
            "invoice",
            "suspended",
            "claim",
            "authenticate",
            "reactivate",
            "passcode",
            "urgent",
        }

        self.shortener_domains = {
            "bit.ly",
            "goo.gl",
            "tinyurl.com",
            "t.co",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "rebrand.ly",
            "cutt.ly",
            "shorte.st",
            "t.ly",
            "bl.ink",
            "tiny.cc",
            "rb.gy",
        }

        self.phishing_tlds = {
            ".tk",
            ".ml",
            ".ga",
            ".cf",
            ".gq",
            ".xyz",
            ".top",
            ".club",
            ".live",
            ".online",
            ".shop",
            ".work",
            ".cam",
            ".buzz",
            ".click",
        }

        self.blacklisted_domains = {
            "paypal.secure-login.com",
            "apple.security.com",
            "goog1e.com",
            "rnicrosoft.com",
            "faceb00k.com",
            "secure-microsoft.com",
            "verify-paypal.com",
            "login-update-security.com",
            "amazon-customersupport.net",
        }

        self.suspicious_url_patterns = {
            "http://",  # Non-HTTPS
            "@",  # user@host.com URLs (phishing trick)
            "login.",  # login.paypal.support
            "-secure",  # paypal-secure.com
            "--",  # long confusing subdomains
            "cdn.",  # fake content delivery or disguised links
        }

        # Compiled regex patterns for performance
        self.ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        self.hex_pattern = re.compile(r"%[0-9a-fA-F]{2}")
        self.digit_ratio_threshold = 0.3  # If >30% of URL is digits

        # Risk score weights
        self.risk_weights = {
            "blacklisted_domain": 0.8,
            "suspicious_tld": 0.6,
            "ip_in_url": 0.7,
            "shortener_domain": 0.5,
            "suspicious_keyword": 0.4,
            "http_protocol": 0.5,
            "at_symbol": 0.7,
            "hex_encoding": 0.6,
            "high_digit_ratio": 0.4,
            "long_subdomain": 0.3,
            "suspicious_path": 0.5,
            "brand_mismatch": 0.9,
        }

        # Multiprocessing setup
        self.pool = multiprocessing.Pool(processes=4)
        self.result_queue = multiprocessing.Queue()
        self.running = multiprocessing.Value("b", True)

    def analyze_url(self, url: str) -> PhishingResult:
        """Main analysis function that checks all phishing indicators"""
        reasons = []
        risk_score = 0.0

        # Normalize URL
        url = url.lower().strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        # Parse URL components
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        fragment = parsed.fragment

        # Extract domain parts
        ext = tldextract.extract(domain)
        subdomain = ext.subdomain
        main_domain = ext.domain
        tld = "." + ext.suffix

        # 1. Check against blacklists
        if domain in self.blacklisted_domains:
            reasons.append("Blacklisted domain")
            risk_score += self.risk_weights["blacklisted_domain"]

        # 2. Check TLD
        if tld in self.phishing_tlds:
            reasons.append(f"Suspicious TLD: {tld}")
            risk_score += self.risk_weights["suspicious_tld"]

        # 3. Check for IP address in URL
        if self.ip_pattern.search(domain):
            reasons.append("IP address in URL")
            risk_score += self.risk_weights["ip_in_url"]

        # 4. Check URL shorteners
        if any(shortener in domain for shortener in self.shortener_domains):
            reasons.append("URL shortener domain")
            risk_score += self.risk_weights["shortener_domain"]

        # 5. Check protocol
        if url.startswith("http://"):
            reasons.append("Insecure HTTP protocol")
            risk_score += self.risk_weights["http_protocol"]

        # 6. Check for @ symbol (obfuscation)
        if "@" in url:
            reasons.append("@ symbol in URL (obfuscation)")
            risk_score += self.risk_weights["at_symbol"]

        # 7. Check for hex encoding
        if self.hex_pattern.search(url):
            reasons.append("Hex encoding in URL")
            risk_score += self.risk_weights["hex_encoding"]

        # 8. Check digit ratio
        digit_ratio = sum(c.isdigit() for c in url) / len(url)
        if digit_ratio > self.digit_ratio_threshold:
            reasons.append(f"High digit ratio ({digit_ratio:.0%})")
            risk_score += self.risk_weights["high_digit_ratio"]

        # 9. Check subdomain length
        if len(subdomain.split(".")) > 3:
            reasons.append("Long subdomain chain")
            risk_score += self.risk_weights["long_subdomain"]

        # 10. Check path for suspicious keywords
        path_keywords = set(path.split("/")) & self.suspicious_keywords
        if path_keywords:
            reasons.append(f"Suspicious path keywords: {', '.join(path_keywords)}")
            risk_score += self.risk_weights["suspicious_path"]

        # 11. Check for brand impersonation
        if main_domain in {"paypal", "google", "microsoft", "apple", "amazon"}:
            if f"{main_domain}.{ext.suffix}" not in self.trusted_domains:
                reasons.append(f"Possible brand impersonation: {main_domain}")
                risk_score += self.risk_weights["brand_mismatch"]

        # 12. Check for suspicious patterns
        for pattern in self.suspicious_url_patterns:
            if pattern in url:
                reasons.append(f"Suspicious URL pattern: {pattern}")
                risk_score += self.risk_weights.get(pattern, 0.4)

        # Cap risk score at 1.0
        risk_score = min(1.0, risk_score)

        return PhishingResult(
            url=url,
            is_phishing=risk_score >= 0.65,  # Threshold can be adjusted
            risk_score=risk_score,
            reasons=reasons,
            timestamp=datetime.utcnow().isoformat(),
        )

    def live_monitor(self, packet_data: Dict):
        """Process network packets for live monitoring"""
        if "http" in packet_data:
            url = packet_data["http"].get("host", "") + packet_data["http"].get(
                "path", ""
            )
            if url:
                # Use multiprocessing for parallel analysis
                self.pool.apply_async(
                    self.analyze_url, args=(url,), callback=self.handle_result
                )

    def manual_check(self, url: str) -> PhishingResult:
        """Manual check initiated by user"""
        return self.analyze_url(url)

    def handle_result(self, result: PhishingResult):
        """Callback for processing results from multiprocessing"""
        if result.is_phishing:
            alert_msg = {
                "type": "phishing_alert",
                "url": result.url,
                "risk_score": result.risk_score,
                "reasons": result.reasons,
                "timestamp": result.timestamp,
            }
            # Put result in queue for main process to handle
            self.result_queue.put(alert_msg)

    def start(self):
        """Start the detector"""
        self.running.value = True
        print("Phishing detector started in live mode")

    def stop(self):
        """Stop the detector"""
        self.running.value = False
        self.pool.close()
        self.pool.join()
        print("Phishing detector stopped")

