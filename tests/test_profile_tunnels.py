"""Tests for SSH tunnel management within profiles."""
import configparser
from pathlib import Path
import sys

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app.profiles import (
    create_profile,
    add_tunnel,
    update_tunnel,
    delete_tunnel,
    load_profiles,
    PROFILES_FILE,
)


def _load_cfg() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profile_tunnels_test_config.ini"))
    return cfg


def test_add_tunnel_and_storage(tmp_path):
    cfg = _load_cfg()
    profiles_file = tmp_path / PROFILES_FILE

    key = tmp_path / cfg["profile"]["ssh_key_filename"]
    key.touch()
    create_profile(cfg["profile"]["name"], key, file_path=profiles_file)

    add_tunnel(
        cfg["profile"]["name"],
        cfg["tunnel"]["name"],
        cfg["tunnel"]["ssh_host"],
        cfg["tunnel"]["username"],
        int(cfg["tunnel"]["local_port"]),
        cfg["tunnel"]["remote_host"],
        int(cfg["tunnel"]["remote_port"]),
        int(cfg["tunnel"]["ssh_port"]),
        [d.strip() for d in cfg["tunnel"]["dns_names"].split(",") if d.strip()],
        file_path=profiles_file,
    )

    stored = load_profiles(profiles_file)
    tunnels = stored[0].get("tunnels", [])
    assert len(tunnels) == 1
    t = tunnels[0]
    assert t["name"] == cfg["tunnel"]["name"]
    assert t["local_port"] == int(cfg["tunnel"]["local_port"])
    assert t["remote_host"] == cfg["tunnel"]["remote_host"]
    assert t["remote_port"] == int(cfg["tunnel"]["remote_port"])
    assert t["ssh_host"] == cfg["tunnel"]["ssh_host"]
    assert t["username"] == cfg["tunnel"]["username"]
    assert t["ssh_port"] == int(cfg["tunnel"]["ssh_port"])
    assert t["dns_names"] == [
        d.strip() for d in cfg["tunnel"]["dns_names"].split(",") if d.strip()
    ]


def test_add_tunnel_without_dns_name(tmp_path):
    cfg = _load_cfg()
    profiles_file = tmp_path / PROFILES_FILE

    key = tmp_path / cfg["profile"]["ssh_key_filename"]
    key.touch()
    create_profile(cfg["profile"]["name"], key, file_path=profiles_file)

    add_tunnel(
        cfg["profile"]["name"],
        cfg["no_dns_tunnel"]["name"],
        cfg["no_dns_tunnel"]["ssh_host"],
        cfg["no_dns_tunnel"]["username"],
        int(cfg["no_dns_tunnel"]["local_port"]),
        cfg["no_dns_tunnel"]["remote_host"],
        int(cfg["no_dns_tunnel"]["remote_port"]),
        file_path=profiles_file,
    )

    stored = load_profiles(profiles_file)
    tunnels = stored[0].get("tunnels", [])
    assert len(tunnels) == 1
    t = tunnels[0]
    assert t["dns_names"] == []
    assert t["ssh_port"] == 22


def test_update_existing_tunnel(tmp_path):
    cfg = _load_cfg()
    profiles_file = tmp_path / PROFILES_FILE

    key = tmp_path / cfg["profile"]["ssh_key_filename"]
    key.touch()
    create_profile(cfg["profile"]["name"], key, file_path=profiles_file)

    add_tunnel(
        cfg["profile"]["name"],
        cfg["tunnel"]["name"],
        cfg["tunnel"]["ssh_host"],
        cfg["tunnel"]["username"],
        int(cfg["tunnel"]["local_port"]),
        cfg["tunnel"]["remote_host"],
        int(cfg["tunnel"]["remote_port"]),
        int(cfg["tunnel"]["ssh_port"]),
        [d.strip() for d in cfg["tunnel"]["dns_names"].split(",") if d.strip()],
        file_path=profiles_file,
    )

    update_tunnel(
        cfg["profile"]["name"],
        cfg["tunnel"]["name"],
        cfg["updated_tunnel"]["name"],
        cfg["updated_tunnel"]["ssh_host"],
        cfg["updated_tunnel"]["username"],
        int(cfg["updated_tunnel"]["local_port"]),
        cfg["updated_tunnel"]["remote_host"],
        int(cfg["updated_tunnel"]["remote_port"]),
        int(cfg["updated_tunnel"]["ssh_port"]),
        [d.strip() for d in cfg["updated_tunnel"]["dns_names"].split(",") if d.strip()],
        file_path=profiles_file,
    )

    stored = load_profiles(profiles_file)
    t = stored[0]["tunnels"][0]
    assert t["name"] == cfg["updated_tunnel"]["name"]
    assert t["local_port"] == int(cfg["updated_tunnel"]["local_port"])
    assert t["remote_host"] == cfg["updated_tunnel"]["remote_host"]
    assert t["remote_port"] == int(cfg["updated_tunnel"]["remote_port"])
    assert t["ssh_host"] == cfg["updated_tunnel"]["ssh_host"]
    assert t["username"] == cfg["updated_tunnel"]["username"]
    assert t["ssh_port"] == int(cfg["updated_tunnel"]["ssh_port"])
    assert t["dns_names"] == [
        d.strip()
        for d in cfg["updated_tunnel"]["dns_names"].split(",")
        if d.strip()
    ]


def test_delete_tunnel(tmp_path):
    cfg = _load_cfg()
    profiles_file = tmp_path / PROFILES_FILE

    key = tmp_path / cfg["profile"]["ssh_key_filename"]
    key.touch()
    create_profile(cfg["profile"]["name"], key, file_path=profiles_file)

    add_tunnel(
        cfg["profile"]["name"],
        cfg["tunnel"]["name"],
        cfg["tunnel"]["ssh_host"],
        cfg["tunnel"]["username"],
        int(cfg["tunnel"]["local_port"]),
        cfg["tunnel"]["remote_host"],
        int(cfg["tunnel"]["remote_port"]),
        int(cfg["tunnel"]["ssh_port"]),
        [d.strip() for d in cfg["tunnel"]["dns_names"].split(",") if d.strip()],
        file_path=profiles_file,
    )

    removed = delete_tunnel(
        cfg["profile"]["name"], cfg["tunnel"]["name"], file_path=profiles_file
    )
    assert removed is True

    stored = load_profiles(profiles_file)
    assert stored[0].get("tunnels", []) == []
