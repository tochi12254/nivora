from pydantic import AnyHttpUrl
from typing import List, Optional
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Cybersecurity Monitoring System"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "Real-time network threat detection API"
    SQLALCHEMY_DATABASE_URL: str = "sqlite+aiosqlite:///./security.db"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    # For PostgreSQL use:
    # DATABASE_URL: PostgresDsn = "postgresql+asyncpg://user:password@localhost/dbname"

    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:4000 ",
        "http://127.0.0.1:4000",
    ]


    REQUIRE_SOCKET_AUTH: bool = True
    PROJECT_NAME: str = "eCyber"
    NETWORK_INTERFACE: str = "Wi-Fi"  # or your interface
    DEBUG: bool = False
    DOCS: bool = True  # Disable in production
    PRODUCTION: bool = False

    # Redis for production scaling
    REDIS_URL: str = "redis://localhost:6379/0"

    # Settings for MitigationEngine
    FIREWALL_API_URL: Optional[str] = "http://127.0.0.1:8000/firewall"
    FIREWALL_API_KEY: Optional[str] = None # Example: "changeme_firewall_api_key"
    THREAT_INTEL_API_URL: Optional[str] = "http://127.0.0.1:8000/intel/update"
    NAC_API_URL: Optional[str] = "http://127.0.0.1:8000/nac/quarantine" # Corrected typo from local127.0.0.1
    DNS_CONTROLLER_API_URL: Optional[str] = "http://127.0.0.1:8000/dns"
    DNS_CONTROLLER_API_KEY: Optional[str] = None # Example: "changeme_dns_api_key"
    
    DASHBOARD_API_URL: Optional[str] = "http://localhost:8081" # For SIEM/Dashboard integration
    DASHBOARD_API_KEY: Optional[str] = None # Example: "changeme_dashboard_api_key"
    
    # Optional: If these dashboard settings also need to be configurable
    DASHBOARD_MAX_RETRIES: int = 3
    DASHBOARD_RETRY_DELAY: int = 5 # seconds
    DASHBOARD_TIMEOUT: int = 10 # seconds

    # GeoIP Service URL for SystemMonitor
    GEOIP_SERVICE_URL_TEMPLATE: Optional[str] = "http://ip-api.com/json/{ip}"

    # ThreatIntelligenceService feed URLs
    THREATFOX_URL: Optional[str] = "https://threatfox.abuse.ch/export/json/recent/"
    CIRCL_CVE_URL: Optional[str] = "https://cve.circl.lu/api/last/10"

    class Config:
        case_sensitive = True
        env_file = ".env"


settings = Settings()
