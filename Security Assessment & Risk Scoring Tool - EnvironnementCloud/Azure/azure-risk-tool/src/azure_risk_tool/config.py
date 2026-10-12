from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    endpoint: str = os.getenv("TOPAZ_ENDPOINT", "https://localhost:8899")
    credential_scope: str = os.getenv(
        "TOPAZ_CREDENTIAL_SCOPE",
        "https://topaz.local.dev:8899/.default",
    )
    storage_endpoint: str = os.getenv("TOPAZ_STORAGE_ENDPOINT", "https://localhost:8891")
    subscription_id: str = os.getenv(
        "AZURE_SUBSCRIPTION_ID",
        "11111111-1111-1111-1111-111111111111",
    )
    location: str = os.getenv("AZURE_LOCATION", "westeurope")
    verify_tls: bool = os.getenv("TOPAZ_VERIFY_TLS", "false").lower() == "true"
    timeout: int = int(os.getenv("AZURE_RISK_TIMEOUT", "30"))
    output_dir: Path = Path(os.getenv("AZURE_RISK_OUTPUT", "output"))
