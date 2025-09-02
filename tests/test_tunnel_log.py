"""Tests for logging tunnel start/stop events to the log section."""

import configparser
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    """Load configuration for tunnel log tests."""
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


class DummyLogText:
    """Simple stand-in for tk.Text to capture log output."""

    def __init__(self):
        self.state = "disabled"
        self.content = ""

    def configure(self, **kwargs):
        if "state" in kwargs:
            self.state = kwargs["state"]

    def insert(self, index, text):
        self.content += text

    def see(self, index):  # pragma: no cover - no behaviour required
        pass


def test_start_tunnel_appends_log(monkeypatch) -> None:
    cfg = _load_cfg()
    app = _make_app(monkeypatch, cfg)

    profile_name = cfg["profile"]["name"]
    tunnel_cfg = cfg["tunnel"]
    tunnel_name = tunnel_cfg["name"]
    ssh_key = Path(cfg["profile"]["ssh_dir"]) / cfg["profile"]["ssh_key_filename"]
    profile_ip = cfg["profile"]["ip"]

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

    class DummyForwarder:
        def __init__(self, **kwargs):
            self.started = False

        def start(self):
            self.started = True

        @property
        def is_active(self):
            return self.started

    monkeypatch.setattr(ui, "SSHTunnelForwarder", DummyForwarder)
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: None)
    app._on_tunnel_select = lambda *a, **k: None
    app._update_highlights = lambda *a, **k: None

    app.log_text = DummyLogText()
    app.profile_controller.active_tunnels = {}
    app._on_start_tunnel()

    expected = f"Started tunnel '{tunnel_name}' for profile '{profile_name}'"
    assert expected in app.log_text.content
    assert app.log_text.state == "disabled"


def test_stop_tunnel_appends_log(monkeypatch) -> None:
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

    app.profile_controller.active_tunnels = {(profile_name, tunnel_name): DummyForwarder()}
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: None)
    app._on_tunnel_select = lambda *a, **k: None
    app._update_highlights = lambda *a, **k: None

    app.log_text = DummyLogText()
    app._on_stop_tunnel()

    expected = f"Stopped tunnel '{tunnel_name}' for profile '{profile_name}'"
    assert expected in app.log_text.content
    assert app.log_text.state == "disabled"
