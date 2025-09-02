"""Tests ensuring profile operations do not show success popups."""
import configparser
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    """Load configuration values used for profile tests."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profiles_test_config.ini"))
    return cfg


def test_new_profile_skips_success_popup(monkeypatch) -> None:
    """Creating a profile should not display a success message box."""
    cfg = _load_cfg()

    # Prepare bare application instance
    root = object()
    with patch.object(ui.LighthouseApp, "_setup_logging", lambda self: None), \
         patch.object(ui.LighthouseApp, "_build_ui", lambda self: None):
        app = ui.LighthouseApp(root, cfg)

    # Dummy treeview and tk constant
    class DummyTreeview:
        def __init__(self):
            self.items = []
        def insert(self, parent, index, values):
            self.items.append(values)
    app.profile_list = DummyTreeview()
    monkeypatch.setattr(ui, "tk", SimpleNamespace(END="end"))

    # Patch dialogs and profile creation
    monkeypatch.setattr(app.profile_controller, "load_profiles", lambda: [])
    class DummyDialog:
        def __init__(self, *_, **__):
            self.result = (
                cfg["profile1"]["name"],
                cfg["profile1"]["ssh_key_filename"],
                None,
            )
    monkeypatch.setattr(ui, "ProfileDialog", DummyDialog)
    def fake_create(name, key_path, ip):
        return {"name": name, "ip": cfg["expected"]["first_ip"]}
    monkeypatch.setattr(app.profile_controller, "create_profile", fake_create)

    called = {}
    def fake_showinfo(*args, **kwargs):
        called["showinfo"] = True
    monkeypatch.setattr(ui.messagebox, "showinfo", fake_showinfo)
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)

    app._on_new_profile()

    assert app.profile_list.items == [
        (cfg['profile1']['name'], cfg['expected']['first_ip'])
    ]
    assert "showinfo" not in called


def test_edit_profile_skips_success_popup(monkeypatch) -> None:
    """Editing a profile should not display a success message box."""
    cfg = _load_cfg()
    root = object()
    with patch.object(ui.LighthouseApp, "_setup_logging", lambda self: None), \
         patch.object(ui.LighthouseApp, "_build_ui", lambda self: None):
        app = ui.LighthouseApp(root, cfg)

    class DummyTreeview:
        def __init__(self):
            self.items = [(cfg['profile1']['name'], cfg['expected']['first_ip'])]
        def selection(self):
            return ("item0",)
        def item(self, item_id, option=None, **kwargs):
            if option == "values" and not kwargs:
                return self.items[0]
            if 'values' in kwargs:
                self.items[0] = kwargs['values']
    app.profile_list = DummyTreeview()

    monkeypatch.setattr(
        app.profile_controller,
        "load_profiles",
        lambda: [{"name": cfg["profile1"]["name"], "ip": cfg["expected"]["first_ip"]}],
    )
    class DummyDialog:
        def __init__(self, *_, **__):
            self.result = (
                cfg["updated_profile"]["name"],
                cfg["updated_profile"]["ssh_key_filename"],
                cfg["updated_profile"]["ip"],
            )
    monkeypatch.setattr(ui, "ProfileDialog", DummyDialog)
    def fake_update(orig, new, key_path, ip):
        return {"name": new, "ip": cfg["expected"]["updated_ip"]}
    monkeypatch.setattr(app.profile_controller, "update_profile", fake_update)

    called = {}
    monkeypatch.setattr(ui.messagebox, "showinfo", lambda *a, **k: called.setdefault("showinfo", True))
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: None)

    app._on_edit_profile()

    assert app.profile_list.items == [
        (cfg['updated_profile']['name'], cfg['expected']['updated_ip'])
    ]
    assert "showinfo" not in called


def test_delete_profile_skips_popups(monkeypatch) -> None:
    """Deleting a profile should not display informational message boxes."""
    cfg = _load_cfg()
    root = object()
    with patch.object(ui.LighthouseApp, "_setup_logging", lambda self: None), \
         patch.object(ui.LighthouseApp, "_build_ui", lambda self: None):
        app = ui.LighthouseApp(root, cfg)

    class DummyTreeview:
        def __init__(self):
            self.items = [(cfg['profile1']['name'], cfg['expected']['first_ip'])]
            self.deleted = []
        def selection(self):
            return ("item0",)
        def item(self, item_id, option=None):
            return self.items[0]
        def delete(self, item_id):
            self.deleted.append(self.items.pop(0))
    app.profile_list = DummyTreeview()

    monkeypatch.setattr(ui.messagebox, "askyesno", lambda *a, **k: True)
    called = {}
    monkeypatch.setattr(ui.messagebox, "showinfo", lambda *a, **k: called.setdefault("showinfo", True))
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: called.setdefault("showwarning", True))
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(app.profile_controller, "delete_profile", lambda name: True)

    app._on_delete_profile()

    assert app.profile_list.items == []
    assert "showinfo" not in called and "showwarning" not in called
