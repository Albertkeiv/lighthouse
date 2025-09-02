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
