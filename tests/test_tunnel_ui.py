import configparser
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    """Load configuration values for tunnel UI tests."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profile_tunnels_test_config.ini"))
    return cfg


def _make_app(monkeypatch, cfg):
    root = object()
    with patch.object(ui.LighthouseApp, "_setup_logging", lambda self: None), \
         patch.object(ui.LighthouseApp, "_build_ui", lambda self: None):
        app = ui.LighthouseApp(root, cfg)
    monkeypatch.setattr(ui, "tk", SimpleNamespace(END="end"))
    return app


def test_new_tunnel_skips_success_popup(monkeypatch) -> None:
    cfg = _load_cfg()
    app = _make_app(monkeypatch, cfg)

    class DummyProfileList:
        def selection(self):
            return ("item0",)
        def item(self, item_id, option=None, **kwargs):
            if option == "values" and not kwargs:
                return (cfg["profile"]["name"], "")

    class DummyTreeview:
        def __init__(self):
            self.items = []
        def insert(self, _parent, _index, values):
            self.items.append(values)
    app.profile_list = DummyProfileList()
    app.tunnel_list = DummyTreeview()

    monkeypatch.setattr(
        ui,
        "load_profiles",
        lambda: [{"name": cfg["profile"]["name"], "tunnels": []}],
    )

    class DummyDialog:
        def __init__(self, *_, **__):
            self.result = (
                cfg["tunnel"]["name"],
                cfg["tunnel"]["ssh_host"],
                cfg["tunnel"]["username"],
                int(cfg["tunnel"]["local_port"]),
                cfg["tunnel"]["remote_host"],
                int(cfg["tunnel"]["remote_port"]),
                int(cfg["tunnel"]["ssh_port"]),
                [d.strip() for d in cfg["tunnel"]["dns_names"].split(",") if d.strip()],
            )
    monkeypatch.setattr(ui, "TunnelDialog", DummyDialog)

    def _add_tunnel(profile, name, ssh_host, username, local, host, remote, ssh_port, dns, *_, **__):
        assert dns == [
            d.strip() for d in cfg["tunnel"]["dns_names"].split(",") if d.strip()
        ]
        assert ssh_host == cfg["tunnel"]["ssh_host"]
        assert username == cfg["tunnel"]["username"]
        assert ssh_port == int(cfg["tunnel"]["ssh_port"])
        return {"name": cfg["tunnel"]["name"]}
    app = ui.LighthouseApp(root, cfg)
    monkeypatch.setattr(app.profile_controller, "add_tunnel", _add_tunnel)

    called = {}
    monkeypatch.setattr(ui.messagebox, "showinfo", lambda *a, **k: called.setdefault("showinfo", True))
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: None)

    app._on_new_tunnel()

    target = f"{cfg['tunnel']['remote_host']}:{cfg['tunnel']['remote_port']}"
    assert app.tunnel_list.items == [(cfg["tunnel"]["name"], target)]
    assert "showinfo" not in called


def test_edit_tunnel_skips_success_popup(monkeypatch) -> None:
    cfg = _load_cfg()
    app = _make_app(monkeypatch, cfg)

    class DummyProfileList:
        def selection(self):
            return ("item0",)
        def item(self, item_id, option=None, **kwargs):
            return (cfg["profile"]["name"], "")

    class DummyTreeview:
        def __init__(self):
            target = f"{cfg['tunnel']['remote_host']}:{cfg['tunnel']['remote_port']}"
            self.items = {"item0": (cfg["tunnel"]["name"], target)}
        def selection(self):
            return ("item0",)
        def item(self, item_id, option=None, **kwargs):
            if option == "values" and not kwargs:
                return self.items[item_id]
            if "values" in kwargs:
                self.items[item_id] = kwargs["values"]
    app.profile_list = DummyProfileList()
    app.tunnel_list = DummyTreeview()

    monkeypatch.setattr(
        ui,
        "load_profiles",
        lambda: [
            {
                "name": cfg["profile"]["name"],
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
                    }
                ],
            }
        ],
    )

    class DummyDialog:
        def __init__(self, *_, **__):
            self.result = (
                cfg["updated_tunnel"]["name"],
                cfg["updated_tunnel"]["ssh_host"],
                cfg["updated_tunnel"]["username"],
                int(cfg["updated_tunnel"]["local_port"]),
                cfg["updated_tunnel"]["remote_host"],
                int(cfg["updated_tunnel"]["remote_port"]),
                int(cfg["updated_tunnel"]["ssh_port"]),
                [
                    d.strip()
                    for d in cfg["updated_tunnel"]["dns_names"].split(",")
                    if d.strip()
                ],
            )
    monkeypatch.setattr(ui, "TunnelDialog", DummyDialog)

    def _update_tunnel(
        profile,
        orig,
        new,
        ssh_host,
        username,
        local,
        host,
        remote,
        ssh_port,
        dns,
        *_,
        **__,
    ):
        assert dns == [
            d.strip()
            for d in cfg["updated_tunnel"]["dns_names"].split(",")
            if d.strip()
        ]
        assert ssh_host == cfg["updated_tunnel"]["ssh_host"]
        assert username == cfg["updated_tunnel"]["username"]
        assert ssh_port == int(cfg["updated_tunnel"]["ssh_port"])
        return None
    monkeypatch.setattr(app.profile_controller, "update_tunnel", _update_tunnel)

    called = {}
    monkeypatch.setattr(ui.messagebox, "showinfo", lambda *a, **k: called.setdefault("showinfo", True))
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: None)

    app._on_edit_tunnel()

    updated_target = f"{cfg['updated_tunnel']['remote_host']}:{cfg['updated_tunnel']['remote_port']}"
    assert list(app.tunnel_list.items.values()) == [(cfg["updated_tunnel"]["name"], updated_target)]
    assert "showinfo" not in called


def test_delete_tunnel_skips_popups(monkeypatch) -> None:
    cfg = _load_cfg()
    app = _make_app(monkeypatch, cfg)

    class DummyProfileList:
        def selection(self):
            return ("item0",)
        def item(self, item_id, option=None, **kwargs):
            return (cfg["profile"]["name"], "")

    class DummyTreeview:
        def __init__(self):
            target = f"{cfg['tunnel']['remote_host']}:{cfg['tunnel']['remote_port']}"
            self.items = {"item0": (cfg["tunnel"]["name"], target)}
        def selection(self):
            return ("item0",)
        def item(self, item_id, option=None, **kwargs):
            return self.items[item_id]
        def delete(self, item_id):
            self.items.pop(item_id)
    app.profile_list = DummyProfileList()
    app.tunnel_list = DummyTreeview()

    monkeypatch.setattr(ui.messagebox, "askyesno", lambda *a, **k: True)
    monkeypatch.setattr(app.profile_controller, "delete_tunnel", lambda *a, **k: True)

    called = {}
    monkeypatch.setattr(ui.messagebox, "showinfo", lambda *a, **k: called.setdefault("showinfo", True))
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: called.setdefault("showwarning", True))
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)

    app._on_delete_tunnel()

    assert app.tunnel_list.items == {}
    assert "showinfo" not in called and "showwarning" not in called

