import logging
from pathlib import Path
from typing import Dict, List, Union

from ..ssh_keys import SSH_KEYS_FILE, load_keys, save_keys


class KeyService:
    """Service layer for managing SSH key entries."""

    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    def load_keys(self, file_path: Union[str, Path] = SSH_KEYS_FILE) -> List[Dict[str, str]]:
        return load_keys(file_path)

    def create_key(
        self,
        name: str,
        ssh_key_path: Union[str, Path],
        description: str,
        file_path: Union[str, Path] = SSH_KEYS_FILE,
    ) -> Dict[str, str]:
        keys = load_keys(file_path)
        key_path = Path(ssh_key_path).expanduser()
        if not key_path.exists():
            raise FileNotFoundError(f"SSH key not found: {key_path}")
        if any(k.get("name") == name for k in keys):
            raise ValueError(f"SSH key '{name}' already exists")
        key = {"name": name, "path": str(key_path), "description": description}
        keys.append(key)
        save_keys(keys, file_path)
        self.logger.info("SSH key '%s' created", name)
        return key

    def delete_key(
        self, name: str, file_path: Union[str, Path] = SSH_KEYS_FILE
    ) -> bool:
        keys = load_keys(file_path)
        remaining = [k for k in keys if k.get("name") != name]
        if len(remaining) == len(keys):
            return False
        save_keys(remaining, file_path)
        self.logger.info("SSH key '%s' deleted", name)
        return True

    def update_key(
        self,
        original_name: str,
        new_name: str,
        ssh_key_path: Union[str, Path],
        description: str,
        file_path: Union[str, Path] = SSH_KEYS_FILE,
    ) -> Dict[str, str]:
        keys = load_keys(file_path)
        key = next((k for k in keys if k.get("name") == original_name), None)
        if key is None:
            raise ValueError(f"SSH key '{original_name}' not found")
        key_path = Path(ssh_key_path).expanduser()
        if not key_path.exists():
            raise FileNotFoundError(f"SSH key not found: {key_path}")
        if new_name != original_name and any(k.get("name") == new_name for k in keys):
            raise ValueError(f"SSH key '{new_name}' already exists")
        key.update({"name": new_name, "path": str(key_path), "description": description})
        save_keys(keys, file_path)
        self.logger.info("SSH key '%s' updated", original_name)
        return key
