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
