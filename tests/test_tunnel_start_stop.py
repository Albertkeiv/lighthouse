"""Tests for starting and stopping tunnels."""

import configparser
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    """Load configuration for tunnel start/stop tests."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profile_tunnels_test_config.ini"))
    return cfg


def _make_app(monkeypatch, cfg):
    """Create minimal application instance for tests."""
    root = object()
    with patch.object(ui.LighthouseApp, "_setup_logging", lambda self: None), \
         patch.object(ui.LighthouseApp, "_build_ui", lambda self: None):
        app = ui.LighthouseApp(root, cfg)
    monkeypatch.setattr(ui, "tk", SimpleNamespace(END="end"))
    return app


def test_start_tunnel_invokes_forwarder(monkeypatch, tmp_path) -> None:
    cfg = _load_cfg()
    cfg["hosts"]["file"] = str(tmp_path / cfg["hosts"]["file"])
    app = _make_app(monkeypatch, cfg)

    profile_name = cfg["profile"]["name"]
    tunnel_cfg = cfg["tunnel"]
    tunnel_name = tunnel_cfg["name"]
    ssh_key = Path(cfg["profile"]["ssh_dir"]) / cfg["profile"]["ssh_key_filename"]
    profile_ip = cfg["profile"]["ip"]
    hosts_file = Path(cfg["hosts"]["file"])
    hosts_file.write_text("")

    class DummyProfileList:
        def selection(self):
            return ("item0",)

        def item(self, _id, option=None, **kwargs):
            return (profile_name, "")

    class DummyTunnelList:
        def selection(self):
            return ("item0",)

        def item(self, _id, option=None, **kwargs):
            return (tunnel_name, "")

    app.profile_list = DummyProfileList()
    app.tunnel_list = DummyTunnelList()

    profiles = [
        {
            "name": profile_name,
            "ssh_key": str(ssh_key),
            "ip": profile_ip,
            "tunnels": [
                {
                    "name": tunnel_name,
                    "local_port": int(tunnel_cfg["local_port"]),
                    "remote_host": tunnel_cfg["remote_host"],
                    "remote_port": int(tunnel_cfg["remote_port"]),
                    "ssh_host": tunnel_cfg["ssh_host"],
                    "username": tunnel_cfg["username"],
                    "ssh_port": int(tunnel_cfg["ssh_port"]),
                    "dns_names": [
                        d.strip()
                        for d in tunnel_cfg["dns_names"].split(",")
                        if d.strip()
                    ],
                }
            ],
        }
    ]
    monkeypatch.setattr(ui, "load_profiles", lambda: profiles)

    called = {}

    class DummyForwarder:
        def __init__(self, **kwargs):
            called["kwargs"] = kwargs
            self.started = False

        def start(self):
            self.started = True

        @property
        def is_active(self):
            return self.started

    monkeypatch.setattr(ui, "SSHTunnelForwarder", DummyForwarder)
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: None)

    app.profile_controller.active_tunnels = {}
    app._on_start_tunnel()

    expected_kwargs = {
        "ssh_address_or_host": (tunnel_cfg["ssh_host"], int(tunnel_cfg["ssh_port"])),
        "ssh_username": tunnel_cfg["username"],
        "ssh_pkey": str(ssh_key),
        "ssh_host_key": None,
        "host_pkey_directories": [],
        "allow_agent": False,
        "ssh_config_file": None,
        "local_bind_address": (profile_ip, int(tunnel_cfg["local_port"])),
        "remote_bind_address": (tunnel_cfg["remote_host"], int(tunnel_cfg["remote_port"])),
    }

    dns_line = " ".join([
        profile_ip,
        *[
            d.strip()
            for d in tunnel_cfg["dns_names"].split(",")
            if d.strip()
        ],
    ])
    block_text = (
        f"#### Managed by Lighthouse profile {profile_name} ####\n"
        f"{dns_line}\n"
        f"#### End block Lighthouse profile {profile_name} ####\n"
    )

    assert called["kwargs"] == expected_kwargs
    assert (profile_name, tunnel_name) in app.profile_controller.active_tunnels
    assert hosts_file.read_text() == block_text


def test_stop_tunnel_stops_forwarder(monkeypatch, tmp_path) -> None:
    cfg = _load_cfg()
    cfg["hosts"]["file"] = str(tmp_path / cfg["hosts"]["file"])
    app = _make_app(monkeypatch, cfg)

    profile_name = cfg["profile"]["name"]
    tunnel_name = cfg["tunnel"]["name"]
    hosts_file = Path(cfg["hosts"]["file"])
    dns_line = " ".join([
        cfg["profile"]["ip"],
        *[
            d.strip()
            for d in cfg["tunnel"]["dns_names"].split(",")
            if d.strip()
        ],
    ])
    block_text = (
        f"#### Managed by Lighthouse profile {profile_name} ####\n"
        f"{dns_line}\n"
        f"#### End block Lighthouse profile {profile_name} ####\n"
    )
    hosts_file.write_text(block_text)

    class DummyProfileList:
        def selection(self):
            return ("item0",)

        def item(self, _id, option=None, **kwargs):
            return (profile_name, "")

    class DummyTunnelList:
        def selection(self):
            return ("item0",)

        def item(self, _id, option=None, **kwargs):
            return (tunnel_name, "")

    app.profile_list = DummyProfileList()
    app.tunnel_list = DummyTunnelList()

    class DummyForwarder:
        def __init__(self):
            self.stopped = False
            self._active = True

        def stop(self):
            self.stopped = True
            self._active = False

        @property
        def is_active(self):
            return self._active

    fwd = DummyForwarder()
    app.profile_controller.active_tunnels = {(profile_name, tunnel_name): fwd}

    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: None)

    app._on_stop_tunnel()

    assert fwd.stopped is True
    assert (profile_name, tunnel_name) not in app.profile_controller.active_tunnels
    assert hosts_file.read_text() == ""

