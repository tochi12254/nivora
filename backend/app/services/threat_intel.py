# backend/app/services/threat_intel.py
import json
import asyncio
from datetime import datetime
from typing import Dict, List, Optional
import aiohttp
import aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
import logging

logger = logging.getLogger("threat_intel")
from ..core.config import Settings

settings = Settings()

class ThreatIntelligenceService:
    def __init__(self, db_session_factory):
        self.db_session_factory = db_session_factory
        self.settings = settings
        self.redis_client = None
        self._init_complete = False

    async def initialize(self):
        """Initialize connections to external services"""
        try:
            # Initialize Redis client if configured
            if self.settings.REDIS_URL:
                self.redis_client = await aioredis.from_url(
                    self.settings.REDIS_URL,
                    max_connections=10,
                    decode_responses=False
                )
                logger.info("Redis client initialized")
            
            # Test connections
            await self._test_connections()
            self._init_complete = True
        except Exception as e:
            logger.error(f"ThreatIntel initialization failed: {str(e)}")
            raise

    async def _test_connections(self):
        """Test external connections"""
        if self.redis_client:
            try:
                await self.redis_client.ping()
            except Exception as e:
                logger.warning(f"Redis ping failed: {str(e)}")
                self.redis_client = None

    async def shutdown(self):
        """Cleanup resources"""
        if self.redis_client:
            await self.redis_client.close()
            logger.info("Redis client closed")

    async def check_ip_reputation(self, ip: str) -> Dict:
        """Main method to check IP reputation"""
        if not self._init_complete:
            raise RuntimeError("ThreatIntelligenceService not initialized")

        # Validate IP format
        try:
            if not self._is_valid_ip(ip):
                return self._neutral_result()
        except ValueError as e:
            logger.warning(f"Invalid IP format: {ip} - {str(e)}")
            return self._neutral_result()

        # Check cache first
        cache_key = f"ip_reputation:{ip}"
        cached_result = await self._get_reputation_cache(cache_key)
        if cached_result:
            return cached_result

        # Default neutral result
        result = self._neutral_result()

        try:
            # Check all feeds in parallel with timeout
            tasks = [
                self._check_abuseipdb(ip),
                self._check_virustotal(ip),
                self._check_ipqualityscore(ip),
                self._check_internal_threat_intel(ip)
            ]
            
            done, pending = await asyncio.wait(
                tasks,
                timeout=self.settings.THREAT_INTEL_TIMEOUT,
                return_when=asyncio.ALL_COMPLETED
            )
            
            # Cancel any pending tasks
            for task in pending:
                task.cancel()

            # Process results
            for task in done:
                try:
                    feed_result = task.result()
                    if feed_result and feed_result.get("is_malicious", False):
                        result = self._merge_results(result, feed_result)
                except Exception as e:
                    logger.warning(f"Error processing threat intel result: {str(e)}")

            # Finalize result
            result = self._finalize_result(result, ip)
            
            # Cache the result
            await self._set_reputation_cache(cache_key, result)

        except asyncio.TimeoutError:
            logger.warning(f"Threat intel check timed out for IP: {ip}")
        except Exception as e:
            logger.error(f"Error checking IP reputation: {str(e)}", exc_info=True)
        
        return result

    def _neutral_result(self) -> Dict:
        """Return a neutral/default result"""
        return {
            "threat_score": 0,
            "threat_types": [],
            "sources": [],
            "first_seen": None,
            "last_seen": datetime.utcnow().isoformat(),
            "confidence": 0,
            "details": {},
            "is_malicious": False
        }

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        # Basic validation - extend as needed
        if not ip or not isinstance(ip, str):
            return False
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    def _merge_results(self, base: Dict, new: Dict) -> Dict:
        """Merge new threat intel result into base result"""
        if not new:
            return base
            
        merged = {
            "threat_score": max(base["threat_score"], new.get("threat_score", 0)),
            "confidence": max(base["confidence"], new.get("confidence", 0)),
            "is_malicious": base["is_malicious"] or new.get("is_malicious", False),
            "threat_types": list(set(base["threat_types"] + new.get("threat_types", []))),
            "sources": list(set(base["sources"] + [new.get("source", "unknown")])),
            "details": {**base["details"], **new.get("details", {})}
        }
        
        # Handle timestamps
        merged["first_seen"] = self._earliest_timestamp(
            base.get("first_seen"), 
            new.get("first_seen")
        )
        merged["last_seen"] = self._latest_timestamp(
            base.get("last_seen"), 
            new.get("last_seen")
        )
        
        return merged

    def _finalize_result(self, result: Dict, ip: str) -> Dict:
        """Finalize the result with post-processing"""
        # Normalize threat score (0-100)
        result["threat_score"] = min(100, max(0, result["threat_score"]))
        
        # Add metadata
        result["ip"] = ip
        result["timestamp"] = datetime.utcnow().isoformat()
        
        # Clean empty values
        result["threat_types"] = [t for t in result["threat_types"] if t]
        result["sources"] = [s for s in result["sources"] if s]
        
        return result

    def _earliest_timestamp(self, ts1: Optional[str], ts2: Optional[str]) -> Optional[str]:
        """Return the earliest of two timestamps"""
        if not ts1:
            return ts2
        if not ts2:
            return ts1
        return min(ts1, ts2)

    def _latest_timestamp(self, ts1: Optional[str], ts2: Optional[str]) -> Optional[str]:
        """Return the latest of two timestamps"""
        if not ts1:
            return ts2
        if not ts2:
            return ts1
        return max(ts1, ts2)

    async def _get_reputation_cache(self, key: str) -> Optional[Dict]:
        """Get cached reputation result"""
        if not self.redis_client:
            return None
            
        try:
            cached = await self.redis_client.get(key)
            if cached:
                return json.loads(cached)
        except Exception as e:
            logger.warning(f"Cache read failed: {str(e)}")
        return None

    async def _set_reputation_cache(self, key: str, value: Dict):
        """Cache reputation result"""
        if not self.redis_client:
            return
            
        try:
            await self.redis_client.set(
                key,
                json.dumps(value),
                ex=self.settings.THREAT_INTEL_CACHE_TTL
            )
        except Exception as e:
            logger.warning(f"Cache write failed: {str(e)}")

    # The feed-specific methods (_check_abuseipdb, _check_virustotal, etc.)
    # remain exactly the same as in the previous implementation
    # ...