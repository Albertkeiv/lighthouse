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


def test_start_tunnel_invokes_popen(monkeypatch) -> None:
    cfg = _load_cfg()
    app = _make_app(monkeypatch, cfg)

    profile_name = cfg["profile"]["name"]
    tunnel_cfg = cfg["tunnel"]
    tunnel_name = tunnel_cfg["name"]
    ssh_key = Path(cfg["profile"]["ssh_dir"]) / cfg["profile"]["ssh_key_filename"]

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

    class DummyProcess:
        def __init__(self, cmd, **kwargs):
            called["cmd"] = cmd
            called["kwargs"] = kwargs

        def poll(self):
            return None

    monkeypatch.setattr(ui.subprocess, "Popen", DummyProcess)
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: None)

    app.active_tunnels = {}
    app._on_start_tunnel()

    expected_cmd = [
        "ssh",
        "-i",
        str(ssh_key),
        "-p",
        tunnel_cfg["ssh_port"],
        "-N",
        "-L",
        f"{tunnel_cfg['local_port']}:{tunnel_cfg['remote_host']}:{tunnel_cfg['remote_port']}",
        f"{tunnel_cfg['username']}@{tunnel_cfg['ssh_host']}",
    ]
    assert called["cmd"] == expected_cmd
    assert (profile_name, tunnel_name) in app.active_tunnels


def test_stop_tunnel_terminates_process(monkeypatch) -> None:
    cfg = _load_cfg()
    app = _make_app(monkeypatch, cfg)

    profile_name = cfg["profile"]["name"]
    tunnel_name = cfg["tunnel"]["name"]

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

    class DummyProcess:
        def __init__(self):
            self.terminated = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            pass

    proc = DummyProcess()
    app.active_tunnels = {(profile_name, tunnel_name): proc}

    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: None)

    app._on_stop_tunnel()

    assert proc.terminated is True
    assert (profile_name, tunnel_name) not in app.active_tunnels

