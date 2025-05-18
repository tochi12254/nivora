# backend/app/services/geoip.py
import aiohttp
from typing import Optional, Dict
import os

class GeoIPService:
    def __init__(self):
        self.api_key = os.getenv('IPAPI_KEY')
        self.base_url = "http://ip-api.com/json/"

    async def lookup(self, ip_address: str) -> Optional[Dict]:
        """Lookup IP address using free ip-api.com service"""
        if not self.api_key:
            return None
            
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}{ip_address}?fields=66842623&lang=en"
                async with session.get(url) as response:
                    data = await response.json()
                    if data.get('status') == 'success':
                        return {
                            'country': data.get('country'),
                            'country_code': data.get('countryCode'),
                            'city': data.get('city'),
                            'postal': data.get('zip'),
                            'latitude': data.get('lat'),
                            'longitude': data.get('lon'),
                            'timezone': data.get('timezone'),
                            'isp': data.get('isp'),
                            'asn': data.get('as'),
                            'org': data.get('org')
                        }
                    return None
        except Exception as e:
            print(f"GeoIP API error: {e}")
            return None