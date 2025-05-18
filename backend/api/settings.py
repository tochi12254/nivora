from typing import Optional,List, Dict, Any
import os
import json

# WebSocket
WS_TOKEN: str = os.getenv(
    "WS_TOKEN",
    "e11ef0134e969d7b4d113322f35edeb8ab704ab325fd762619c63ba801fa41567de1158d7877675dc41db889af4479ba768cdd6df000387c8314a3c7195c12d5",
)

# Security
CORS_ORIGINS: list = json.loads(os.getenv("CORS_ORIGINS", '["*"]'))
ALLOWED_HOSTS: list = json.loads(os.getenv("ALLOWED_HOSTS", '["*"]'))

# SSL
USE_SSL: bool = os.getenv("USE_SSL", "false").lower() == "true"
SSL_KEY_PATH: Optional[str] = os.getenv("SSL_KEY_PATH")
SSL_CERT_PATH: Optional[str] = os.getenv("SSL_CERT_PATH")
SSL_CA_PATH: Optional[str] = os.getenv("SSL_CA_PATH")
