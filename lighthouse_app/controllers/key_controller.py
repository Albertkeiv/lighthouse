from pathlib import Path
from typing import Dict, List, Union

from ..services.key_service import KeyService
from ..ssh_keys import SSH_KEYS_FILE


class KeyController:
    """Controller coordinating SSH key service calls."""

    def __init__(self) -> None:
        self.service = KeyService()

    def load_keys(self, file_path: Union[str, Path] = SSH_KEYS_FILE) -> List[Dict[str, str]]:
        return self.service.load_keys(file_path)

    def create_key(
        self,
        name: str,
        ssh_key_path: Union[str, Path],
        description: str,
        file_path: Union[str, Path] = SSH_KEYS_FILE,
    ) -> Dict[str, str]:
        return self.service.create_key(name, ssh_key_path, description, file_path)

    def update_key(
        self,
        original_name: str,
        new_name: str,
        ssh_key_path: Union[str, Path],
        description: str,
        file_path: Union[str, Path] = SSH_KEYS_FILE,
    ) -> Dict[str, str]:
        return self.service.update_key(
            original_name, new_name, ssh_key_path, description, file_path
        )

    def delete_key(self, name: str, file_path: Union[str, Path] = SSH_KEYS_FILE) -> bool:
        return self.service.delete_key(name, file_path)
