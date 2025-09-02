import json
import logging
from ipaddress import IPv4Network, ip_address
from pathlib import Path
from typing import Dict, List, Union, Optional

# File where profiles are stored
PROFILES_FILE = "profiles.json"
# Network from which automatic profile IPs are allocated
PROFILE_NET = IPv4Network("127.1.1.0/24")


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
    """Return the first free IP address from ``PROFILE_NET``."""
    used_ips = {p.get("ip") for p in existing_profiles}
    for addr in PROFILE_NET.hosts():
        ip = str(addr)
        if ip not in used_ips:
            return ip
    raise RuntimeError("No available IP addresses in 127.1.1.0/24")


def create_profile(
    name: str,
    ssh_key_path: Union[str, Path],
    ip: Optional[str] = None,
    file_path: Union[str, Path] = PROFILES_FILE,
) -> Dict[str, str]:
    """Create and store a new profile.

    Parameters
    ----------
    name: str
        Human-readable profile name.
    ssh_key_path: str | Path
        Path to the SSH private key.
    ip: str, optional
        Specific IP address to assign to the profile. If not provided,
        an address is automatically allocated from ``PROFILE_NET``.
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

    if ip is not None:
        try:
            ip_str = str(ip_address(ip))
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {ip}") from exc
        if any(p.get("ip") == ip_str for p in profiles):
            raise ValueError(f"IP address {ip_str} is already in use")
        logger.info("Manual IP '%s' requested", ip_str)
    else:
        ip_str = _allocate_ip(profiles)
        logger.info("Automatically allocated IP '%s'", ip_str)

    profile = {"name": name, "ip": ip_str, "ssh_key": str(key_path)}
    profiles.append(profile)
    save_profiles(profiles, file_path)
    logger.info("Profile '%s' created with IP %s", name, ip_str)
    return profile


def delete_profile(name: str, file_path: Union[str, Path] = PROFILES_FILE) -> bool:
    """Delete a profile by name.

    Parameters
    ----------
    name: str
        Name of the profile to remove.
    file_path: str | Path, optional
        Path to the profiles JSON file. Defaults to ``PROFILES_FILE``.

    Returns
    -------
    bool
        ``True`` if the profile existed and was removed, ``False`` otherwise.
    """
    logger = logging.getLogger(__name__)
    logger.info("Request to delete profile '%s'", name)

    if not name:
        raise ValueError("Profile name must be provided")

    profiles = load_profiles(file_path)
    remaining = [p for p in profiles if p.get("name") != name]

    if len(remaining) == len(profiles):
        logger.warning("Profile '%s' not found", name)
        return False

    save_profiles(remaining, file_path)
    logger.info("Profile '%s' deleted", name)
    return True


def update_profile(
    original_name: str,
    new_name: str,
    ssh_key_path: Union[str, Path],
    ip: Optional[str] = None,
    file_path: Union[str, Path] = PROFILES_FILE,
) -> Dict[str, str]:
    """Update an existing profile's parameters.

    Parameters
    ----------
    original_name: str
        Name of the profile to update.
    new_name: str
        New human-readable profile name.
    ssh_key_path: str | Path
        Path to the SSH private key.
    ip: str, optional
        New IP address to assign. If ``None`` an address is automatically
        allocated from ``PROFILE_NET``.
    file_path: str | Path, optional
        Path to the profiles JSON file. Defaults to ``PROFILES_FILE``.
    """
    logger = logging.getLogger(__name__)
    logger.info("Request to update profile '%s'", original_name)

    if not new_name:
        raise ValueError("Profile name must be provided")

    key_path = Path(ssh_key_path).expanduser()
    if not key_path.exists():
        raise FileNotFoundError(f"SSH key not found: {key_path}")

    profiles = load_profiles(file_path)
    profile = next((p for p in profiles if p.get("name") == original_name), None)
    if profile is None:
        logger.warning("Profile '%s' not found", original_name)
        raise ValueError(f"Profile '{original_name}' not found")

    if new_name != original_name and any(p.get("name") == new_name for p in profiles):
        raise ValueError(f"Profile '{new_name}' already exists")

    if ip is not None:
        try:
            ip_str = str(ip_address(ip))
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {ip}") from exc
        if any(
            p.get("ip") == ip_str and p.get("name") != original_name for p in profiles
        ):
            raise ValueError(f"IP address {ip_str} is already in use")
        logger.info("Manual IP '%s' requested for profile '%s'", ip_str, original_name)
    else:
        remaining = [p for p in profiles if p.get("name") != original_name]
        ip_str = _allocate_ip(remaining)
        logger.info(
            "Automatically allocated IP '%s' for profile '%s'", ip_str, original_name
        )

    profile.update({"name": new_name, "ssh_key": str(key_path), "ip": ip_str})
    save_profiles(profiles, file_path)
    logger.info("Profile '%s' updated", original_name)
    return profile


def add_tunnel(
    profile_name: str,
    tunnel_name: str,
    ssh_host: str,
    username: str,
    local_port: int,
    remote_host: str,
    remote_port: int,
    ssh_port: int = 22,
    dns_names: Optional[List[str]] = None,
    file_path: Union[str, Path] = PROFILES_FILE,
) -> Dict[str, Union[str, int, List[str]]]:
    """Create and attach an SSH tunnel to a profile.

    Parameters
    ----------
    profile_name: str
        Name of the profile to modify.
    tunnel_name: str
        Unique name for the tunnel.
    ssh_host: str
        Hostname of the SSH server to connect through.
    username: str
        Username for the SSH connection.
    local_port: int
        Local port for the tunnel.
    remote_host: str
        Remote host to connect to.
    remote_port: int
        Remote port to connect to.
    ssh_port: int, optional
        SSH server port. Defaults to ``22``.
    dns_names: list[str], optional
        DNS names associated with the tunnel. Can be an empty list.
    file_path: str | Path, optional
        Path to the profiles JSON file. Defaults to ``PROFILES_FILE``.
    """
    logger = logging.getLogger(__name__)
    dns_names = [str(n).strip() for n in dns_names or [] if str(n).strip()]
    logger.info(
        "Request to add tunnel '%s' to profile '%s' with DNS names '%s'",
        tunnel_name,
        profile_name,
        ", ".join(dns_names),
    )

    if not all([profile_name, tunnel_name, ssh_host, username]):
        raise ValueError(
            "Profile name, tunnel name, SSH host and username must be provided"
        )

    try:
        l_port = int(local_port)
        r_port = int(remote_port)
        s_port = int(ssh_port)
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError("Ports must be integers") from exc

    for port in (l_port, r_port, s_port):
        if not (1 <= port <= 65535):
            raise ValueError(f"Port {port} must be between 1 and 65535")

    if not remote_host:
        raise ValueError("Remote host must be provided")

    profiles = load_profiles(file_path)
    profile = next((p for p in profiles if p.get("name") == profile_name), None)
    if profile is None:
        logger.warning("Profile '%s' not found", profile_name)
        raise ValueError(f"Profile '{profile_name}' not found")

    tunnels = profile.setdefault("tunnels", [])
    if any(t.get("name") == tunnel_name for t in tunnels):
        raise ValueError(
            f"Tunnel '{tunnel_name}' already exists for profile '{profile_name}'"
        )

    tunnel = {
        "name": tunnel_name,
        "ssh_host": ssh_host,
        "username": username,
        "ssh_port": s_port,
        "local_port": l_port,
        "remote_host": remote_host,
        "remote_port": r_port,
        "dns_names": dns_names,
    }
    tunnels.append(tunnel)
    save_profiles(profiles, file_path)
    logger.info("Tunnel '%s' added to profile '%s'", tunnel_name, profile_name)
    return tunnel


def update_tunnel(
    profile_name: str,
    tunnel_name: str,
    new_name: str,
    ssh_host: str,
    username: str,
    local_port: int,
    remote_host: str,
    remote_port: int,
    ssh_port: int = 22,
    dns_names: Optional[List[str]] = None,
    file_path: Union[str, Path] = PROFILES_FILE,
) -> Dict[str, Union[str, int, List[str]]]:
    """Update parameters of an existing SSH tunnel.

    Parameters
    ----------
    profile_name: str
        Name of the profile to modify.
    tunnel_name: str
        Current name of the tunnel to update.
    new_name: str
        New unique name for the tunnel.
    ssh_host: str
        Hostname of the SSH server to connect through.
    username: str
        Username for the SSH connection.
    local_port: int
        Local port for the tunnel.
    remote_host: str
        Remote host to connect to.
    remote_port: int
        Remote port to connect to.
    ssh_port: int, optional
        SSH server port. Defaults to ``22``.
    dns_names: list[str], optional
        DNS names associated with the tunnel. Can be an empty list.
    file_path: str | Path, optional
        Path to the profiles JSON file. Defaults to ``PROFILES_FILE``.
    """
    logger = logging.getLogger(__name__)
    dns_names = [str(n).strip() for n in dns_names or [] if str(n).strip()]
    logger.info(
        "Request to update tunnel '%s' in profile '%s' with DNS names '%s'",
        tunnel_name,
        profile_name,
        ", ".join(dns_names),
    )

    if not all([profile_name, new_name, tunnel_name, ssh_host, username]):
        raise ValueError(
            "Profile name, tunnel names, SSH host and username must be provided"
        )

    try:
        l_port = int(local_port)
        r_port = int(remote_port)
        s_port = int(ssh_port)
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError("Ports must be integers") from exc

    for port in (l_port, r_port, s_port):
        if not (1 <= port <= 65535):
            raise ValueError(f"Port {port} must be between 1 and 65535")

    if not remote_host:
        raise ValueError("Remote host must be provided")

    profiles = load_profiles(file_path)
    profile = next((p for p in profiles if p.get("name") == profile_name), None)
    if profile is None:
        logger.warning("Profile '%s' not found", profile_name)
        raise ValueError(f"Profile '{profile_name}' not found")

    tunnels = profile.get("tunnels", [])
    tunnel = next((t for t in tunnels if t.get("name") == tunnel_name), None)
    if tunnel is None:
        logger.warning(
            "Tunnel '%s' not found for profile '%s'", tunnel_name, profile_name
        )
        raise ValueError(
            f"Tunnel '{tunnel_name}' not found for profile '{profile_name}'"
        )

    if new_name != tunnel_name and any(t.get("name") == new_name for t in tunnels):
        raise ValueError(
            f"Tunnel '{new_name}' already exists for profile '{profile_name}'"
        )

    tunnel.update(
        {
            "name": new_name,
            "ssh_host": ssh_host,
            "username": username,
            "ssh_port": s_port,
            "local_port": l_port,
            "remote_host": remote_host,
            "remote_port": r_port,
            "dns_names": dns_names,
        }
    )
    save_profiles(profiles, file_path)
    logger.info("Tunnel '%s' updated in profile '%s'", tunnel_name, profile_name)
    return tunnel


def delete_tunnel(
    profile_name: str,
    tunnel_name: str,
    file_path: Union[str, Path] = PROFILES_FILE,
) -> bool:
    """Remove an SSH tunnel from a profile."""
    logger = logging.getLogger(__name__)
    logger.info(
        "Request to delete tunnel '%s' from profile '%s'", tunnel_name, profile_name
    )

    if not profile_name or not tunnel_name:
        raise ValueError("Profile name and tunnel name must be provided")

    profiles = load_profiles(file_path)
    profile = next((p for p in profiles if p.get("name") == profile_name), None)
    if profile is None:
        logger.warning("Profile '%s' not found", profile_name)
        raise ValueError(f"Profile '{profile_name}' not found")

    tunnels = profile.get("tunnels", [])
    remaining = [t for t in tunnels if t.get("name") != tunnel_name]
    if len(remaining) == len(tunnels):
        logger.warning(
            "Tunnel '%s' not found for profile '%s'", tunnel_name, profile_name
        )
        return False

    profile["tunnels"] = remaining
    save_profiles(profiles, file_path)
    logger.info(
        "Tunnel '%s' deleted from profile '%s'", tunnel_name, profile_name
    )
    return True
