"""Tests for displaying tunnel information in the status pane."""

import configparser
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    """Load configuration for tunnel info tests."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profile_tunnels_test_config.ini"))
    return cfg


def _make_app(monkeypatch, cfg):
    """Create application instance with minimal UI for testing."""
    root = object()
    with patch.object(ui.LighthouseApp, "_setup_logging", lambda self: None), \
         patch.object(ui.LighthouseApp, "_build_ui", lambda self: None):
        app = ui.LighthouseApp(root, cfg)
    # Dummy tk replacement
    monkeypatch.setattr(ui, "tk", SimpleNamespace(END="end"))
    return app


def test_tunnel_selection_updates_status(monkeypatch) -> None:
    """Selecting a tunnel populates the tunnel info section."""
    cfg = _load_cfg()
    app = _make_app(monkeypatch, cfg)

    class DummyText:
        def __init__(self):
            self.content = ""

        def delete(self, *_args, **_kwargs):
            self.content = ""

        def insert(self, _idx, text):
            self.content += text

    app.status_text = DummyText()

    class DummyProfileList:
        def selection(self):
            return ("item0",)

        def item(self, _item_id, option=None, **_kwargs):
            if option == "values":
                return (cfg["profile"]["name"], "")

    app.profile_list = DummyProfileList()

    class DummyTunnelList:
        def selection(self):
            return ("tunnel0",)

        def item(self, _item_id, option=None, **_kwargs):
            if option == "values":
                target = f"{cfg['tunnel']['remote_host']}:{cfg['tunnel']['remote_port']}"
                return (cfg["tunnel"]["name"], target)

    tunnel_widget = DummyTunnelList()
    app.tunnel_list = tunnel_widget

    profile_data = [
        {
            "name": cfg["profile"]["name"],
            "ip": cfg["profile"]["ip"],
            # Формируем путь к ключу через Path, чтобы поддерживать Windows-пути
            "ssh_key": str(Path(cfg["profile"]["ssh_dir"]) / cfg["profile"]["ssh_key_filename"]),
            "tunnels": [
                {
                    "name": cfg["tunnel"]["name"],
                    "local_port": int(cfg["tunnel"]["local_port"]),
                    "remote_host": cfg["tunnel"]["remote_host"],
                    "remote_port": int(cfg["tunnel"]["remote_port"]),
                    "ssh_host": cfg["tunnel"]["ssh_host"],
                    "username": cfg["tunnel"]["username"],
                    "ssh_port": int(cfg["tunnel"]["ssh_port"]),
                    "dns_names": [
                        d.strip()
                        for d in cfg["tunnel"]["dns_names"].split(",")
                        if d.strip()
                    ],
                    "dns_override": cfg["tunnel"].getboolean("dns_override"),
                }
            ],
        }
    ]

    monkeypatch.setattr(ui, "load_profiles", lambda: profile_data)

    event = SimpleNamespace(widget=tunnel_widget)
    app._on_tunnel_select(event)

    dns_list = [
        d.strip() for d in cfg["tunnel"]["dns_names"].split(",") if d.strip()
    ]
    expected_text = (
        f"Tunnel: {cfg['tunnel']['name']}\n"
        f"Status: {cfg['expected']['tunnel_status']}\n"
        f"DNS: {', '.join(dns_list)}"
    )

    assert app.status_text.content == expected_text

