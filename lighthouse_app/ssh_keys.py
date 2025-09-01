"""Utility functions for storing and editing SSH key entries."""

import json
import logging
from pathlib import Path
from typing import Dict, List, Union

SSH_KEYS_FILE = "ssh_keys.json"


def load_keys(file_path: Union[str, Path] = SSH_KEYS_FILE) -> List[Dict[str, str]]:
    """Load SSH keys from a JSON file."""
    logger = logging.getLogger(__name__)
    path = Path(file_path)
    if not path.exists():
        logger.info("SSH key file %s not found", path)
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if not isinstance(data, list):
            logger.warning("SSH key file %s has invalid format", path)
            return []
        logger.info("Loaded %d SSH keys", len(data))
        return data
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Failed to load SSH keys: %s", exc)
        return []


def save_keys(keys: List[Dict[str, str]], file_path: Union[str, Path] = SSH_KEYS_FILE) -> None:
    """Persist SSH keys to a JSON file."""
    logger = logging.getLogger(__name__)
    path = Path(file_path)
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(keys, handle, indent=2)
        logger.info("Saved %d SSH keys to %s", len(keys), path)
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Failed to save SSH keys: %s", exc)


def create_key(
    name: str,
    ssh_key_path: Union[str, Path],
    description: str,
    file_path: Union[str, Path] = SSH_KEYS_FILE,
) -> Dict[str, str]:
    """Create and store a new SSH key entry."""
    logger = logging.getLogger(__name__)
    logger.info("Request to create SSH key '%s'", name)

    if not name:
        raise ValueError("SSH key name must be provided")

    key_path = Path(ssh_key_path).expanduser()
    if not key_path.exists():
        raise FileNotFoundError(f"SSH key not found: {key_path}")

    keys = load_keys(file_path)
    if any(k.get("name") == name for k in keys):
        raise ValueError(f"SSH key '{name}' already exists")

    key = {"name": name, "path": str(key_path), "description": description}
    keys.append(key)
    save_keys(keys, file_path)
    logger.info("SSH key '%s' created", name)
    return key


def delete_key(name: str, file_path: Union[str, Path] = SSH_KEYS_FILE) -> bool:
    """Delete an SSH key entry by name."""
    logger = logging.getLogger(__name__)
    logger.info("Request to delete SSH key '%s'", name)

    if not name:
        raise ValueError("SSH key name must be provided")

    keys = load_keys(file_path)
    remaining = [k for k in keys if k.get("name") != name]

    if len(remaining) == len(keys):
        logger.warning("SSH key '%s' not found", name)
        return False

    save_keys(remaining, file_path)
    logger.info("SSH key '%s' deleted", name)
    return True


def update_key(
    original_name: str,
    new_name: str,
    ssh_key_path: Union[str, Path],
    description: str,
    file_path: Union[str, Path] = SSH_KEYS_FILE,
) -> Dict[str, str]:
    """Update an existing SSH key entry."""
    logger = logging.getLogger(__name__)
    logger.info("Request to update SSH key '%s'", original_name)

    if not new_name:
        raise ValueError("SSH key name must be provided")

    key_path = Path(ssh_key_path).expanduser()
    if not key_path.exists():
        raise FileNotFoundError(f"SSH key not found: {key_path}")

    keys = load_keys(file_path)
    key = next((k for k in keys if k.get("name") == original_name), None)
    if key is None:
        logger.warning("SSH key '%s' not found", original_name)
        raise ValueError(f"SSH key '{original_name}' not found")

    if new_name != original_name and any(k.get("name") == new_name for k in keys):
        raise ValueError(f"SSH key '{new_name}' already exists")

    key.update({"name": new_name, "path": str(key_path), "description": description})
    save_keys(keys, file_path)
    logger.info("SSH key '%s' updated", original_name)
    return key
