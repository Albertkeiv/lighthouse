import json
import logging
from ipaddress import IPv4Network
from pathlib import Path
from typing import Dict, List, Union

# File where profiles are stored
PROFILES_FILE = "profiles.json"
# Network from which automatic profile IPs are allocated
PROFILE_NET = IPv4Network("127.1.1.0/24")


def load_profiles(file_path: Union[str, Path] = PROFILES_FILE) -> List[Dict[str, str]]:
    """Load profiles from JSON storage."""
    logger = logging.getLogger(__name__)
    path = Path(file_path)
    if not path.exists():
        logger.info("Profiles file %s not found", path)
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, list):
            logger.warning("Profiles file %s has invalid format", path)
            return []
        logger.info("Loaded %d profiles", len(data))
        return data
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Failed to load profiles: %s", exc)
        return []


def save_profiles(profiles: List[Dict[str, str]], file_path: Union[str, Path] = PROFILES_FILE) -> None:
    """Persist profiles to JSON storage."""
    logger = logging.getLogger(__name__)
    path = Path(file_path)
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(profiles, handle, indent=2)
        logger.info("Saved %d profiles to %s", len(profiles), path)
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Failed to save profiles: %s", exc)


def _allocate_ip(existing_profiles: List[Dict[str, str]]) -> str:
    """Return the first free IP address from ``PROFILE_NET``."""
    used_ips = {p.get("ip") for p in existing_profiles}
    for addr in PROFILE_NET.hosts():
        ip = str(addr)
        if ip not in used_ips:
            return ip
    raise RuntimeError("No available IP addresses in 127.1.1.0/24")
