import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from sshtunnel import SSHTunnelForwarder

from ..hosts import HOSTS_FILE, add_hosts_block, remove_hosts_block
from ..profiles import (
    PROFILES_FILE,
    _allocate_ip,
    load_profiles as _load_profiles,
    save_profiles,
)


class ProfileService:
    """Service layer encapsulating profile and tunnel operations."""

    def __init__(self, hosts_file: Optional[Union[str, Path]] = None) -> None:
        """Create the service using a configurable hosts file.

        Parameters
        ----------
        hosts_file: str | Path | None
            Optional explicit path to the hosts file.  When ``None`` the
            default from :data:`lighthouse_app.hosts.HOSTS_FILE` is used.
        """

        if hosts_file is None:
            self.hosts_file = HOSTS_FILE
        else:
            self.hosts_file = Path(hosts_file)
        # Track running tunnels; keys are ``(profile_name, tunnel_name)`` tuples
        self.active_tunnels: Dict[Tuple[str, str], SSHTunnelForwarder] = {}
        # Remember whether DNS override was enabled when starting each tunnel
        # to ensure hosts file is only modified when explicitly requested.
        self.dns_overrides: Dict[Tuple[str, str], bool] = {}
        self.logger = logging.getLogger(__name__)
        self.logger.debug("Using hosts file %s", self.hosts_file)

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
        auto_ip: bool = True,
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
            if auto_ip:
                ip_str = _allocate_ip(profiles)
            else:
                raise ValueError(
                    "IP address must be provided when automatic assignment is disabled"
                )
        profile = {
            "name": name,
            "ip": ip_str,
            "ssh_key": str(key_path),
            "auto_ip": auto_ip,
        }
        profiles.append(profile)
        save_profiles(profiles, file_path)
        self.logger.info(
            "Profile '%s' created with IP %s (auto=%s)", name, ip_str, auto_ip
        )
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
        auto_ip: bool = True,
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
            if auto_ip:
                remaining = [p for p in profiles if p.get("name") != original_name]
                ip_str = profile.get("ip") or _allocate_ip(remaining)
            else:
                raise ValueError(
                    "IP address must be provided when automatic assignment is disabled"
                )
        profile.update(
            {
                "name": new_name,
                "ssh_key": str(key_path),
                "ip": ip_str,
                "auto_ip": auto_ip,
            }
        )
        save_profiles(profiles, file_path)
        self.logger.info("Profile '%s' updated (auto=%s)", original_name, auto_ip)
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
        dns_override: bool = True,
        file_path: Union[str, Path] = PROFILES_FILE,
    ) -> Dict[str, Union[str, int, List[str], bool]]:
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
            "dns_override": bool(dns_override),
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
        dns_override: bool = True,
        file_path: Union[str, Path] = PROFILES_FILE,
    ) -> Dict[str, Union[str, int, List[str], bool]]:
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
                "dns_override": bool(dns_override),
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
        forwarder_cls: type[SSHTunnelForwarder] = SSHTunnelForwarder,
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
        forwarder = forwarder_cls(
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
        dns_override = bool(tunnel.get("dns_override", True))
        self.dns_overrides[key] = dns_override
        if dns_override:
            add_hosts_block(
                profile_name,
                bind_ip,
                tunnel.get("dns_names", []),
                self.hosts_file,
                self.logger,
            )
        else:
            self.logger.info(
                "DNS override disabled for tunnel '%s'; skipping hosts update",
                tunnel_name,
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
        dns_override = self.dns_overrides.pop(key, False)
        if dns_override:
            remove_hosts_block(profile_name, self.hosts_file, self.logger)
        else:
            self.logger.info(
                "DNS override disabled for tunnel '%s'; skipping hosts cleanup",
                tunnel_name,
            )
        self.logger.info(
            "Stopped tunnel '%s' for profile '%s'", tunnel_name, profile_name
        )

    def is_tunnel_active(self, profile_name: str, tunnel_name: str) -> bool:
        forwarder = self.active_tunnels.get((profile_name, tunnel_name))
        return bool(forwarder and forwarder.is_active)

    # ------------------------------------------------------------------
    # Profile lifecycle operations
    # ------------------------------------------------------------------
    def start_profile(
        self,
        profile_name: str,
        file_path: Union[str, Path] = PROFILES_FILE,
        profiles: Optional[List[Dict[str, str]]] = None,
        forwarder_cls: type[SSHTunnelForwarder] = SSHTunnelForwarder,
    ) -> None:
        """Start all tunnels defined for a profile."""
        if profiles is None:
            profiles = self.load_profiles(file_path)
        profile = next((p for p in profiles if p.get("name") == profile_name), None)
        if profile is None:
            raise ValueError(f"Profile '{profile_name}' not found")
        tunnels = profile.get("tunnels", [])
        if not tunnels:
            raise ValueError(f"No tunnels configured for profile '{profile_name}'")
        all_dns: List[str] = []
        for tunnel in tunnels:
            t_name = tunnel.get("name")
            if self.is_tunnel_active(profile_name, t_name):
                self.logger.info(
                    "Tunnel '%s' already running for profile '%s'", t_name, profile_name
                )
                if tunnel.get("dns_override", True):
                    all_dns.extend(tunnel.get("dns_names", []))
                continue
            self.start_tunnel(
                profile_name,
                t_name,
                file_path,
                profiles,
                forwarder_cls,
            )
            if tunnel.get("dns_override", True):
                all_dns.extend(tunnel.get("dns_names", []))
        if all_dns:
            add_hosts_block(
                profile_name,
                profile.get("ip"),
                all_dns,
                self.hosts_file,
                self.logger,
            )
        self.logger.info("Started profile '%s'", profile_name)

    def stop_profile(self, profile_name: str) -> None:
        """Stop all running tunnels for a profile."""
        to_stop = [k for k in list(self.active_tunnels) if k[0] == profile_name]
        if not to_stop:
            raise RuntimeError(f"No tunnels running for profile '{profile_name}'")
        for key in to_stop:
            self.stop_tunnel(*key)
        self.logger.info("Stopped profile '%s'", profile_name)
