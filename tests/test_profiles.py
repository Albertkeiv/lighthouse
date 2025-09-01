"""Tests for profile management."""
import configparser
from pathlib import Path
import sys

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app.profiles import create_profile, load_profiles, PROFILES_FILE


def _load_cfg() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profiles_test_config.ini"))
    return cfg


def test_profile_creation_and_storage(tmp_path):
    cfg = _load_cfg()
    profiles_file = tmp_path / PROFILES_FILE

    key1 = tmp_path / cfg["profile1"]["ssh_key_filename"]
    key1.touch()
    profile1 = create_profile(cfg["profile1"]["name"], key1, profiles_file)
    assert profile1["ip"] == cfg["expected"]["first_ip"]

    key2 = tmp_path / cfg["profile2"]["ssh_key_filename"]
    key2.touch()
    profile2 = create_profile(cfg["profile2"]["name"], key2, profiles_file)
    assert profile2["ip"] == cfg["expected"]["second_ip"]

    stored = load_profiles(profiles_file)
    assert stored[0]["name"] == cfg["profile1"]["name"]
    assert stored[1]["name"] == cfg["profile2"]["name"]
