"""Tests for SSH key management."""
import configparser
from pathlib import Path
import sys

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app.ssh_keys import load_keys, SSH_KEYS_FILE
from lighthouse_app.services.key_service import KeyService


def _load_cfg() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("ssh_keys_test_config.ini"))
    return cfg


def test_key_creation_and_storage(tmp_path):
    cfg = _load_cfg()
    keys_file = tmp_path / SSH_KEYS_FILE

    key1_path = tmp_path / cfg["key1"]["filename"]
    key1_path.touch()
    service = KeyService()
    service.create_key(
        cfg["key1"]["name"],
        key1_path,
        cfg["key1"]["description"],
        file_path=keys_file,
    )

    key2_path = tmp_path / cfg["key2"]["filename"]
    key2_path.touch()
    service.create_key(
        cfg["key2"]["name"],
        key2_path,
        cfg["key2"]["description"],
        file_path=keys_file,
    )

    stored = load_keys(keys_file)
    assert stored[0]["name"] == cfg["key1"]["name"]
    assert stored[1]["description"] == cfg["key2"]["description"]


def test_update_and_delete_key(tmp_path):
    cfg = _load_cfg()
    keys_file = tmp_path / SSH_KEYS_FILE

    key_path = tmp_path / cfg["key1"]["filename"]
    key_path.touch()
    service = KeyService()
    service.create_key(
        cfg["key1"]["name"],
        key_path,
        cfg["key1"]["description"],
        file_path=keys_file,
    )

    updated_path = tmp_path / cfg["updated_key"]["filename"]
    updated_path.touch()
    updated = service.update_key(
        cfg["key1"]["name"],
        cfg["updated_key"]["name"],
        updated_path,
        cfg["updated_key"]["description"],
        file_path=keys_file,
    )
    assert updated["name"] == cfg["expected"]["updated_name"]
    assert updated["description"] == cfg["expected"]["updated_description"]

    removed = service.delete_key(cfg["updated_key"]["name"], file_path=keys_file)
    assert removed is True
    assert load_keys(keys_file) == []
