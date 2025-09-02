import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from sshtunnel import SSHTunnelForwarder

from ..hosts import add_hosts_block, remove_hosts_block
from ..profiles import (
    PROFILES_FILE,
    _allocate_ip,
    load_profiles as _load_profiles,
    save_profiles,
)


class ProfileService:
    """Service layer encapsulating profile and tunnel operations."""

    def __init__(self, hosts_file: Union[str, Path] = "/etc/hosts") -> None:
        self.hosts_file = Path(hosts_file)
        # Track running tunnels; keys are ``(profile_name, tunnel_name)`` tuples
        self.active_tunnels: Dict[Tuple[str, str], SSHTunnelForwarder] = {}
        self.logger = logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # Profile management
    # ------------------------------------------------------------------
    def load_profiles(
        self, file_path: Union[str, Path] = PROFILES_FILE
    ) -> List[Dict[str, str]]:
        """Return profiles stored on disk.

        This thin wrapper logs the access and delegates to the helper
        function that performs the actual file I/O. Any unexpected
        exception is caught to keep the application running smoothly.
        """
        self.logger.debug("Loading profiles from %s", file_path)
        try:
            profiles = _load_profiles(file_path)
            self.logger.debug("Loaded %d profiles", len(profiles))
            return profiles
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Unexpected error loading profiles: %s", exc)
            return []

    def create_profile(
        self,
        name: str,
        ssh_key_path: Union[str, Path],
        ip: Optional[str] = None,
        file_path: Union[str, Path] = PROFILES_FILE,
    ) -> Dict[str, str]:
        profiles = _load_profiles(file_path)
        key_path = Path(ssh_key_path).expanduser()
        if not key_path.exists():
            raise FileNotFoundError(f"SSH key not found: {key_path}")
        if any(p.get("name") == name for p in profiles):
            raise ValueError(f"Profile '{name}' already exists")
        if ip is not None:
            ip_str = str(ip)
            if any(p.get("ip") == ip_str for p in profiles):
                raise ValueError(f"IP address {ip_str} is already in use")
        else:
            ip_str = _allocate_ip(profiles)
        profile = {"name": name, "ip": ip_str, "ssh_key": str(key_path)}
        profiles.append(profile)
        save_profiles(profiles, file_path)
        self.logger.info("Profile '%s' created with IP %s", name, ip_str)
        return profile

    def delete_profile(
        self, name: str, file_path: Union[str, Path] = PROFILES_FILE
    ) -> bool:
        profiles = _load_profiles(file_path)
        remaining = [p for p in profiles if p.get("name") != name]
        if len(remaining) == len(profiles):
            return False
        save_profiles(remaining, file_path)
        self.logger.info("Profile '%s' deleted", name)
        return True

    def update_profile(
        self,
        original_name: str,
        new_name: str,
        ssh_key_path: Union[str, Path],
        ip: Optional[str] = None,
        file_path: Union[str, Path] = PROFILES_FILE,
    ) -> Dict[str, str]:
        profiles = _load_profiles(file_path)
        profile = next((p for p in profiles if p.get("name") == original_name), None)
        if profile is None:
            raise ValueError(f"Profile '{original_name}' not found")
        key_path = Path(ssh_key_path).expanduser()
        if not key_path.exists():
            raise FileNotFoundError(f"SSH key not found: {key_path}")
        if new_name != original_name and any(p.get("name") == new_name for p in profiles):
            raise ValueError(f"Profile '{new_name}' already exists")
        if ip is not None:
            ip_str = str(ip)
            if any(
                p.get("ip") == ip_str and p.get("name") != original_name
                for p in profiles
            ):
                raise ValueError(f"IP address {ip_str} is already in use")
        else:
            remaining = [p for p in profiles if p.get("name") != original_name]
            ip_str = _allocate_ip(remaining)
        profile.update({"name": new_name, "ssh_key": str(key_path), "ip": ip_str})
        save_profiles(profiles, file_path)
        self.logger.info("Profile '%s' updated", original_name)
        return profile

    # ------------------------------------------------------------------
    # Tunnel management (storage)
    # ------------------------------------------------------------------
    def add_tunnel(
        self,
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
        dns_names = [str(n).strip() for n in dns_names or [] if str(n).strip()]
        profiles = _load_profiles(file_path)
        profile = next((p for p in profiles if p.get("name") == profile_name), None)
        if profile is None:
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
            "ssh_port": int(ssh_port),
            "local_port": int(local_port),
            "remote_host": remote_host,
            "remote_port": int(remote_port),
            "dns_names": dns_names,
        }
        tunnels.append(tunnel)
        save_profiles(profiles, file_path)
        self.logger.info("Tunnel '%s' added to profile '%s'", tunnel_name, profile_name)
        return tunnel

    def update_tunnel(
        self,
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
        dns_names = [str(n).strip() for n in dns_names or [] if str(n).strip()]
        profiles = _load_profiles(file_path)
        profile = next((p for p in profiles if p.get("name") == profile_name), None)
        if profile is None:
            raise ValueError(f"Profile '{profile_name}' not found")
        tunnels = profile.get("tunnels", [])
        tunnel = next((t for t in tunnels if t.get("name") == tunnel_name), None)
        if tunnel is None:
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
                "ssh_port": int(ssh_port),
                "local_port": int(local_port),
                "remote_host": remote_host,
                "remote_port": int(remote_port),
                "dns_names": dns_names,
            }
        )
        save_profiles(profiles, file_path)
        self.logger.info(
            "Tunnel '%s' updated in profile '%s'", tunnel_name, profile_name
        )
        return tunnel

    def delete_tunnel(
        self,
        profile_name: str,
        tunnel_name: str,
        file_path: Union[str, Path] = PROFILES_FILE,
    ) -> bool:
        profiles = _load_profiles(file_path)
        profile = next((p for p in profiles if p.get("name") == profile_name), None)
        if profile is None:
            raise ValueError(f"Profile '{profile_name}' not found")
        tunnels = profile.get("tunnels", [])
        remaining = [t for t in tunnels if t.get("name") != tunnel_name]
        if len(remaining) == len(tunnels):
            return False
        profile["tunnels"] = remaining
        save_profiles(profiles, file_path)
        self.logger.info(
            "Tunnel '%s' deleted from profile '%s'", tunnel_name, profile_name
        )
        return True

    # ------------------------------------------------------------------
    # Tunnel lifecycle operations
    # ------------------------------------------------------------------
    def start_tunnel(
        self,
        profile_name: str,
        tunnel_name: str,
        file_path: Union[str, Path] = PROFILES_FILE,
        profiles: Optional[List[Dict[str, str]]] = None,
    ) -> None:
        key = (profile_name, tunnel_name)
        forwarder = self.active_tunnels.get(key)
        if forwarder and forwarder.is_active:
            raise RuntimeError(f"Tunnel '{tunnel_name}' is already running")
        if profiles is None:
            profiles = self.load_profiles(file_path)
        profile = next((p for p in profiles if p.get("name") == profile_name), None)
        tunnel = None
        if profile:
            tunnel = next(
                (t for t in profile.get("tunnels", []) if t.get("name") == tunnel_name),
                None,
            )
        if not profile or not tunnel:
            raise ValueError(
                f"Profile '{profile_name}' or tunnel '{tunnel_name}' not found"
            )
        bind_ip = profile.get("ip")
        if not bind_ip:
            raise ValueError(f"Profile '{profile_name}' has no IP address")
        forwarder = SSHTunnelForwarder(
            ssh_address_or_host=(tunnel.get("ssh_host"), int(tunnel.get("ssh_port"))),
            ssh_username=tunnel.get("username"),
            ssh_pkey=profile.get("ssh_key"),
            ssh_host_key=None,
            host_pkey_directories=[],
            allow_agent=False,
            ssh_config_file=None,
            local_bind_address=(bind_ip, int(tunnel.get("local_port"))),
            remote_bind_address=(tunnel.get("remote_host"), int(tunnel.get("remote_port"))),
        )
        forwarder.start()
        self.active_tunnels[key] = forwarder
        add_hosts_block(
            profile_name,
            bind_ip,
            tunnel.get("dns_names", []),
            self.hosts_file,
            self.logger,
        )
        self.logger.info(
            "Started tunnel '%s' for profile '%s'", tunnel_name, profile_name
        )

    def stop_tunnel(self, profile_name: str, tunnel_name: str) -> None:
        key = (profile_name, tunnel_name)
        forwarder = self.active_tunnels.get(key)
        if not forwarder or not forwarder.is_active:
            raise RuntimeError(f"Tunnel '{tunnel_name}' is not running")
        forwarder.stop()
        del self.active_tunnels[key]
        remove_hosts_block(profile_name, self.hosts_file, self.logger)
        self.logger.info(
            "Stopped tunnel '%s' for profile '%s'", tunnel_name, profile_name
        )

    def is_tunnel_active(self, profile_name: str, tunnel_name: str) -> bool:
        forwarder = self.active_tunnels.get((profile_name, tunnel_name))
        return bool(forwarder and forwarder.is_active)
