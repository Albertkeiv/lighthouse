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

    class DummyListbox:
        def __init__(self):
            self.items = []
        def insert(self, index, value):
            self.items.append(value)
    app.profile_list = DummyProfileList()
    app.tunnel_list = DummyListbox()

    monkeypatch.setattr(
        ui,
        "load_profiles",
        lambda: [{"name": cfg["profile"]["name"], "tunnels": []}],
    )

    class DummyDialog:
        def __init__(self, *_, **__):
            self.result = (
                cfg["tunnel"]["name"],
                int(cfg["tunnel"]["local_port"]),
                cfg["tunnel"]["remote_host"],
                int(cfg["tunnel"]["remote_port"]),
            )
    monkeypatch.setattr(ui, "TunnelDialog", DummyDialog)
    monkeypatch.setattr(ui, "add_tunnel", lambda *a, **k: {"name": cfg["tunnel"]["name"]})

    called = {}
    monkeypatch.setattr(ui.messagebox, "showinfo", lambda *a, **k: called.setdefault("showinfo", True))
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: None)

    app._on_new_tunnel()

    assert app.tunnel_list.items == [cfg["tunnel"]["name"]]
    assert "showinfo" not in called


def test_edit_tunnel_skips_success_popup(monkeypatch) -> None:
    cfg = _load_cfg()
    app = _make_app(monkeypatch, cfg)

    class DummyProfileList:
        def selection(self):
            return ("item0",)
        def item(self, item_id, option=None, **kwargs):
            return (cfg["profile"]["name"], "")

    class DummyListbox:
        def __init__(self):
            self.items = [cfg["tunnel"]["name"]]
        def curselection(self):
            return (0,)
        def get(self, index):
            return self.items[index]
        def delete(self, index):
            self.items.pop(index)
        def insert(self, index, value):
            self.items.insert(index, value)
    app.profile_list = DummyProfileList()
    app.tunnel_list = DummyListbox()

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
                    }
                ],
            }
        ],
    )

    class DummyDialog:
        def __init__(self, *_, **__):
            self.result = (
                cfg["updated_tunnel"]["name"],
                int(cfg["updated_tunnel"]["local_port"]),
                cfg["updated_tunnel"]["remote_host"],
                int(cfg["updated_tunnel"]["remote_port"]),
            )
    monkeypatch.setattr(ui, "TunnelDialog", DummyDialog)
    monkeypatch.setattr(ui, "update_tunnel", lambda *a, **k: None)

    called = {}
    monkeypatch.setattr(ui.messagebox, "showinfo", lambda *a, **k: called.setdefault("showinfo", True))
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: None)

    app._on_edit_tunnel()

    assert app.tunnel_list.items == [cfg["updated_tunnel"]["name"]]
    assert "showinfo" not in called


def test_delete_tunnel_skips_popups(monkeypatch) -> None:
    cfg = _load_cfg()
    app = _make_app(monkeypatch, cfg)

    class DummyProfileList:
        def selection(self):
            return ("item0",)
        def item(self, item_id, option=None, **kwargs):
            return (cfg["profile"]["name"], "")

    class DummyListbox:
        def __init__(self):
            self.items = [cfg["tunnel"]["name"]]
        def curselection(self):
            return (0,)
        def get(self, index):
            return self.items[index]
        def delete(self, index):
            self.items.pop(index)
    app.profile_list = DummyProfileList()
    app.tunnel_list = DummyListbox()

    monkeypatch.setattr(ui.messagebox, "askyesno", lambda *a, **k: True)
    monkeypatch.setattr(ui, "delete_tunnel", lambda *a, **k: True)

    called = {}
    monkeypatch.setattr(ui.messagebox, "showinfo", lambda *a, **k: called.setdefault("showinfo", True))
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: called.setdefault("showwarning", True))
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)

    app._on_delete_tunnel()

    assert app.tunnel_list.items == []
    assert "showinfo" not in called and "showwarning" not in called

