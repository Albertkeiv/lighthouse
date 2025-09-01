import json
import logging
from ipaddress import IPv4Network
from pathlib import Path
from typing import Dict, List, Union

# File where profiles are stored
PROFILES_FILE = "profiles.json"
# Network from which profile IPs are allocated
PROFILE_NET = IPv4Network("127.0.0.0/8")


def load_profiles(file_path: Union[str, Path] = PROFILES_FILE) -> List[Dict[str, str]]:
    """Load profiles from JSON storage.

    Parameters
    ----------
    file_path: str | Path
        Location of the JSON file with profiles.
    """
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
    """Return the first free IP address from PROFILE_NET.

    Skips 127.0.0.1 and addresses already present in ``existing_profiles``.
    """
    used_ips = {p.get("ip") for p in existing_profiles}
    for addr in PROFILE_NET.hosts():
        ip = str(addr)
        if ip == "127.0.0.1":
            continue
        if ip not in used_ips:
            return ip
    raise RuntimeError("No available IP addresses in 127.0.0.0/8")


def create_profile(name: str, ssh_key_path: Union[str, Path], file_path: Union[str, Path] = PROFILES_FILE) -> Dict[str, str]:
    """Create and store a new profile.

    Parameters
    ----------
    name: str
        Human-readable profile name.
    ssh_key_path: str | Path
        Path to the SSH private key.
    file_path: str | Path, optional
        Path to the profiles JSON file. Defaults to ``PROFILES_FILE``.
    """
    logger = logging.getLogger(__name__)
    logger.info("Request to create profile '%s'", name)

    if not name:
        raise ValueError("Profile name must be provided")

    key_path = Path(ssh_key_path).expanduser()
    if not key_path.exists():
        raise FileNotFoundError(f"SSH key not found: {key_path}")

    profiles = load_profiles(file_path)
    if any(p.get("name") == name for p in profiles):
        raise ValueError(f"Profile '{name}' already exists")

    ip = _allocate_ip(profiles)
    profile = {"name": name, "ip": ip, "ssh_key": str(key_path)}
    profiles.append(profile)
    save_profiles(profiles, file_path)
    logger.info("Profile '%s' created with IP %s", name, ip)
    return profile
