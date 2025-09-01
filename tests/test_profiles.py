"""Tests for profile management."""
import configparser
from pathlib import Path
import sys

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app.profiles import (
    create_profile,
    load_profiles,
    delete_profile,
    PROFILES_FILE,
)


def _load_cfg() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profiles_test_config.ini"))
    return cfg


def test_profile_creation_and_storage(tmp_path):
    cfg = _load_cfg()
    profiles_file = tmp_path / PROFILES_FILE

    key1 = tmp_path / cfg["profile1"]["ssh_key_filename"]
    key1.touch()
    profile1 = create_profile(
        cfg["profile1"]["name"], key1, file_path=profiles_file
    )
    assert profile1["ip"] == cfg["expected"]["first_ip"]

    key2 = tmp_path / cfg["profile2"]["ssh_key_filename"]
    key2.touch()
    profile2 = create_profile(
        cfg["profile2"]["name"], key2, file_path=profiles_file
    )
    assert profile2["ip"] == cfg["expected"]["second_ip"]

    stored = load_profiles(profiles_file)
    assert stored[0]["name"] == cfg["profile1"]["name"]
    assert stored[1]["name"] == cfg["profile2"]["name"]


def test_manual_ip_assignment(tmp_path):
    cfg = _load_cfg()
    profiles_file = tmp_path / PROFILES_FILE

    key = tmp_path / cfg["manual_profile"]["ssh_key_filename"]
    key.touch()
    manual_ip = cfg["manual_profile"]["ip"]
    profile = create_profile(
        cfg["manual_profile"]["name"], key, ip=manual_ip, file_path=profiles_file
    )
    assert profile["ip"] == cfg["expected"]["manual_ip"]


def test_manual_ip_duplicate_error(tmp_path):
    cfg = _load_cfg()
    profiles_file = tmp_path / PROFILES_FILE

    key1 = tmp_path / cfg["manual_profile"]["ssh_key_filename"]
    key1.touch()
    manual_ip = cfg["expected"]["manual_ip"]
    create_profile(
        cfg["manual_profile"]["name"], key1, ip=manual_ip, file_path=profiles_file
    )

    key2 = tmp_path / cfg["duplicate_profile"]["ssh_key_filename"]
    key2.touch()
    import pytest

    with pytest.raises(ValueError):
        create_profile(
            cfg["duplicate_profile"]["name"],
            key2,
            ip=manual_ip,
            file_path=profiles_file,
        )


def test_delete_profile(tmp_path):
    cfg = _load_cfg()
    profiles_file = tmp_path / PROFILES_FILE

    key1 = tmp_path / cfg["profile1"]["ssh_key_filename"]
    key1.touch()
    create_profile(cfg["profile1"]["name"], key1, file_path=profiles_file)

    key2 = tmp_path / cfg["profile2"]["ssh_key_filename"]
    key2.touch()
    create_profile(cfg["profile2"]["name"], key2, file_path=profiles_file)

    removed = delete_profile(cfg["profile1"]["name"], file_path=profiles_file)
    assert removed is True
    remaining = load_profiles(profiles_file)
    assert len(remaining) == 1
    assert remaining[0]["name"] == cfg["profile2"]["name"]


def test_delete_nonexistent_profile(tmp_path):
    cfg = _load_cfg()
    profiles_file = tmp_path / PROFILES_FILE

    key1 = tmp_path / cfg["profile1"]["ssh_key_filename"]
    key1.touch()
    create_profile(cfg["profile1"]["name"], key1, file_path=profiles_file)

    removed = delete_profile(
        cfg["nonexistent_profile"]["name"], file_path=profiles_file
    )
    assert removed is False
    profiles = load_profiles(profiles_file)
    assert len(profiles) == 1
