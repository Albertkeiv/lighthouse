from pathlib import Path
from typing import Dict, List, Optional, Union, Tuple
from sshtunnel import SSHTunnelForwarder

from ..profiles import PROFILES_FILE
from ..services.profile_service import ProfileService


class ProfileController:
    """Controller orchestrating profile and tunnel operations."""

    def __init__(self, hosts_file: Union[str, Path] = "/etc/hosts") -> None:
        self.service = ProfileService(hosts_file)

    @property
    def active_tunnels(self) -> Dict[Tuple[str, str], SSHTunnelForwarder]:
        """Expose active tunnels for UI access.

        The service maintains the mapping, but the UI tests interact with
        the controller.  Providing this proxy keeps the public API stable
        while still delegating storage to the service layer.
        """
        return self.service.active_tunnels

    @active_tunnels.setter
    def active_tunnels(self, value: Dict[Tuple[str, str], SSHTunnelForwarder]) -> None:
        self.service.active_tunnels = value

    # Profile operations -------------------------------------------------
    def load_profiles(self, file_path: Union[str, Path] = PROFILES_FILE) -> List[Dict[str, str]]:
        return self.service.load_profiles(file_path)

    def create_profile(
        self,
        name: str,
        ssh_key_path: Union[str, Path],
        ip: Optional[str] = None,
        file_path: Union[str, Path] = PROFILES_FILE,
    ) -> Dict[str, str]:
        return self.service.create_profile(name, ssh_key_path, ip, file_path)

    def update_profile(
        self,
        original_name: str,
        new_name: str,
        ssh_key_path: Union[str, Path],
        ip: Optional[str] = None,
        file_path: Union[str, Path] = PROFILES_FILE,
    ) -> Dict[str, str]:
        return self.service.update_profile(original_name, new_name, ssh_key_path, ip, file_path)

    def delete_profile(self, name: str, file_path: Union[str, Path] = PROFILES_FILE) -> bool:
        return self.service.delete_profile(name, file_path)

    # Tunnel operations --------------------------------------------------
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
        return self.service.add_tunnel(
            profile_name,
            tunnel_name,
            ssh_host,
            username,
            local_port,
            remote_host,
            remote_port,
            ssh_port,
            dns_names,
            file_path,
        )

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
        return self.service.update_tunnel(
            profile_name,
            tunnel_name,
            new_name,
            ssh_host,
            username,
            local_port,
            remote_host,
            remote_port,
            ssh_port,
            dns_names,
            file_path,
        )

    def delete_tunnel(
        self,
        profile_name: str,
        tunnel_name: str,
        file_path: Union[str, Path] = PROFILES_FILE,
    ) -> bool:
        return self.service.delete_tunnel(profile_name, tunnel_name, file_path)

    # Tunnel lifecycle ---------------------------------------------------
    def start_tunnel(
        self,
        profile_name: str,
        tunnel_name: str,
        file_path: Union[str, Path] = PROFILES_FILE,
    ) -> None:
        profiles = self.load_profiles()
        self.service.start_tunnel(profile_name, tunnel_name, file_path, profiles)

    def stop_tunnel(self, profile_name: str, tunnel_name: str) -> None:
        self.service.stop_tunnel(profile_name, tunnel_name)

    def is_tunnel_active(self, profile_name: str, tunnel_name: str) -> bool:
        return self.service.is_tunnel_active(profile_name, tunnel_name)
