"""Tests for SSHKeyManager UI behaviour."""

import configparser
from pathlib import Path
import sys
from types import SimpleNamespace

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    """Load test configuration for SSH key manager."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("ssh_keys_test_config.ini"))
    return cfg


def test_manager_uses_table_and_double_click(monkeypatch) -> None:
    """Treeview should show name and description and support double-click edit."""
    cfg = _load_cfg()
    inserted: list = []
    headings: dict = {}
    bindings: dict = {}
    geometry_calls: list = []

    class DummyTreeview:
        def __init__(self, master=None, columns=(), show=""):
            pass
        def heading(self, column, text=""):
            headings[column] = text
        def pack(self, *args, **kwargs):
            pass
        def insert(self, parent, index, values=()):
            inserted.append(values)
        def bind(self, event, callback):
            bindings[event] = callback
        def selection(self):
            return ()
        def item(self, item_id):
            return {"values": ()}
        def delete(self, item_id):
            pass

    class DummyButton:
        def __init__(self, master=None, text="", command=None):
            pass
        def pack(self, *args, **kwargs):
            pass

    class DummyToplevel:
        def __init__(self, master=None):
            pass
        def title(self, text):
            pass
        def geometry(self, geom):
            geometry_calls.append(geom)

    fake_tk = SimpleNamespace(
        Toplevel=DummyToplevel,
        Button=DummyButton,
        BOTH="both",
        END="end",
    )
    fake_ttk = SimpleNamespace(Treeview=DummyTreeview)

    monkeypatch.setattr(ui, "tk", fake_tk)
    monkeypatch.setattr(ui, "ttk", fake_ttk)
    monkeypatch.setattr(
        ui,
        "load_ssh_keys",
        lambda: [
            {
                "name": cfg["key1"]["name"],
                "description": cfg["key1"]["description"],
            }
        ],
    )

    manager = ui.SSHKeyManager(None)

    expected_values = (cfg["key1"]["name"], cfg["key1"]["description"])
    assert inserted == [expected_values]
    assert headings["name"] == "Name"
    assert headings["description"] == "Description"
    expected_width = cfg["ui"]["window_width"]
    assert any(g.startswith(expected_width) for g in geometry_calls)

    # Verify double-click triggers edit
    calls = []
    manager._on_edit = lambda: calls.append(True)
    bindings["<Double-1>"](None)
    assert calls


def test_add_key_skips_success_popup(monkeypatch) -> None:
    """Adding a key should not display a success message box."""
    cfg = _load_cfg()
    inserted: list = []

    class DummyTreeview:
        def __init__(self, *_, **__):
            self.items = {}
        def heading(self, *_, **__):
            pass
        def pack(self, *_, **__):
            pass
        def insert(self, parent, index, values=()):
            self.items["item1"] = {"values": values}
            inserted.append(values)
        def bind(self, *_, **__):
            pass
        def selection(self):
            return ()
        def item(self, item_id, **kwargs):
            return self.items.get(item_id, {"values": ()})
        def delete(self, item_id):
            self.items.pop(item_id, None)

    class DummyButton:
        def __init__(self, *_, **__):
            pass
        def pack(self, *_, **__):
            pass

    class DummyToplevel:
        def __init__(self, *_, **__):
            pass
        def title(self, *_, **__):
            pass
        def geometry(self, *_, **__):
            pass

    fake_tk = SimpleNamespace(
        Toplevel=DummyToplevel,
        Button=DummyButton,
        BOTH="both",
        END="end",
    )
    fake_ttk = SimpleNamespace(Treeview=DummyTreeview)

    monkeypatch.setattr(ui, "tk", fake_tk)
    monkeypatch.setattr(ui, "ttk", fake_ttk)
    monkeypatch.setattr(ui, "load_ssh_keys", lambda: [])

    class DummyDialog:
        def __init__(self, *_, **__):
            self.result = (
                cfg["key1"]["name"],
                cfg["key1"]["filename"],
                cfg["key1"]["description"],
            )

    monkeypatch.setattr(ui, "SSHKeyDialog", DummyDialog)

    def fake_create(name, path, desc):
        return {"name": name, "description": desc}

    monkeypatch.setattr(ui, "create_ssh_key", fake_create)

    called = {}

    def fake_showinfo(*args, **kwargs):
        called["showinfo"] = True

    monkeypatch.setattr(ui.messagebox, "showinfo", fake_showinfo)

    manager = ui.SSHKeyManager(None)
    manager._on_add()

    assert inserted
    assert "showinfo" not in called


def test_edit_key_skips_success_popup(monkeypatch) -> None:
    """Editing a key should not display a success message box."""
    cfg = _load_cfg()

    class DummyTreeview:
        def __init__(self, *_, **__):
            self.items = {}
            self.last_id = ""
        def heading(self, *_, **__):
            pass
        def pack(self, *_, **__):
            pass
        def insert(self, parent, index, values=()):
            self.last_id = f"item{len(self.items)+1}"
            self.items[self.last_id] = {"values": values}
            return self.last_id
        def bind(self, *_, **__):
            pass
        def selection(self):
            return [self.last_id] if self.last_id else []
        def item(self, item_id, **kwargs):
            if "values" in kwargs:
                self.items[item_id] = {"values": kwargs["values"]}
            return self.items.get(item_id, {"values": ()})
        def delete(self, item_id):
            self.items.pop(item_id, None)

    class DummyButton:
        def __init__(self, *_, **__):
            pass
        def pack(self, *_, **__):
            pass

    class DummyToplevel:
        def __init__(self, *_, **__):
            pass
        def title(self, *_, **__):
            pass
        def geometry(self, *_, **__):
            pass

    fake_tk = SimpleNamespace(
        Toplevel=DummyToplevel,
        Button=DummyButton,
        BOTH="both",
        END="end",
    )
    fake_ttk = SimpleNamespace(Treeview=DummyTreeview)

    monkeypatch.setattr(ui, "tk", fake_tk)
    monkeypatch.setattr(ui, "ttk", fake_ttk)

    monkeypatch.setattr(
        ui,
        "load_ssh_keys",
        lambda: [
            {
                "name": cfg["key1"]["name"],
                "description": cfg["key1"]["description"],
                "path": cfg["key1"]["filename"],
            }
        ],
    )

    class DummyDialog:
        def __init__(self, *_, **__):
            self.result = (
                cfg["updated_key"]["name"],
                cfg["updated_key"]["filename"],
                cfg["updated_key"]["description"],
            )

    monkeypatch.setattr(ui, "SSHKeyDialog", DummyDialog)

    def fake_update(original, new_name, path, desc):
        return {"name": new_name, "description": desc}

    monkeypatch.setattr(ui, "update_ssh_key", fake_update)

    called = {}

    def fake_showinfo(*args, **kwargs):
        called["showinfo"] = True

    monkeypatch.setattr(ui.messagebox, "showinfo", fake_showinfo)

    manager = ui.SSHKeyManager(None)
    manager._on_edit()

    assert manager.key_table.item(manager.key_table.last_id)["values"][0] == cfg["updated_key"]["name"]
    assert "showinfo" not in called
