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


def test_manager_displays_description_and_sets_width(monkeypatch) -> None:
    """List should contain name and description and window should be wider."""
    cfg = _load_cfg()
    inserted = []
    geometry_calls = []

    class DummyListbox:
        def __init__(self, master=None):
            pass
        def pack(self, *args, **kwargs):
            pass
        def insert(self, index, item):
            inserted.append(item)
        def curselection(self):
            return ()
        def get(self, index):
            return inserted[index]
        def delete(self, index):
            inserted.pop(index)

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
        Listbox=DummyListbox,
        Button=DummyButton,
        BOTH="both",
        END="end",
    )

    monkeypatch.setattr(ui, "tk", fake_tk)
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

    ui.SSHKeyManager(None)

    expected_item = f"{cfg['key1']['name']} - {cfg['key1']['description']}"
    assert inserted == [expected_item]
    expected_width = cfg["ui"]["window_width"]
    assert any(g.startswith(expected_width) for g in geometry_calls)
