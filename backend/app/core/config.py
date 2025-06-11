from pydantic import AnyHttpUrl, Extra
from typing import List, Optional
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Cybersecurity Monitoring System"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Real-time network threat detection API"
    SQLALCHEMY_DATABASE_URL: str = "sqlite+aiosqlite:///./security.db"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days

    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:4000",
        "http://127.0.0.1:4000",
    ]

    REQUIRE_SOCKET_AUTH: bool = True
    NETWORK_INTERFACE: str = "Wi-Fi"
    DEBUG: bool = False
    DOCS: bool = True
    PRODUCTION: bool = False

    REDIS_URL: str = "redis://localhost:6379/0"

    FIREWALL_API_URL: Optional[str] = "http://127.0.0.1:8000/firewall"
    FIREWALL_API_KEY: Optional[str] = None
    THREAT_INTEL_API_URL: Optional[str] = "http://127.0.0.1:8000/intel/update"
    NAC_API_URL: Optional[str] = "http://127.0.0.1:8000/nac/quarantine"
    DNS_CONTROLLER_API_URL: Optional[str] = "http://127.0.0.1:8000/dns"
    DNS_CONTROLLER_API_KEY: Optional[str] = None

    DASHBOARD_API_URL: Optional[str] = "http://localhost:8081"
    DASHBOARD_API_KEY: Optional[str] = None
    DASHBOARD_MAX_RETRIES: int = 3
    DASHBOARD_RETRY_DELAY: int = 5  # seconds
    DASHBOARD_TIMEOUT: int = 10     # seconds

    GEOIP_SERVICE_URL_TEMPLATE: Optional[str] = "http://ip-api.com/json/{ip}"
    THREATFOX_URL: Optional[str] = "https://threatfox.abuse.ch/export/json/recent/"
    CIRCL_CVE_URL: Optional[str] = "https://cve.circl.lu/api/last/10"

    class Config:
        case_sensitive = True
        env_file = ".env"
        extra = Extra.ignore

# Singleton settings instance
settings = Settings()
