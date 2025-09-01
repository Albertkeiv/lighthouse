"""Verify that pane layout restoration occurs after panes are created."""

import configparser
from pathlib import Path
import types

import pytest

# Ensure module import
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _expected_coords():
    """Read coordinates from the sample configuration file."""
    cfg = configparser.ConfigParser()
    sample = Path(__file__).with_name("pane_layout_sample.ini")
    cfg.read(sample)
    return [
        cfg.getint("panes", key)
        for key in sorted(cfg["panes"], key=lambda k: int(k.split("_")[-1]))
    ]


def test_restore_pane_layout_after_panes(monkeypatch):
    coords = _expected_coords()

    # Fake Tkinter module with minimal functionality to avoid GUI dependency
    class DummyWidget:
        def __init__(self, *args, **kwargs):
            pass

        def grid(self, *args, **kwargs):
            pass

        def pack(self, *args, **kwargs):
            pass

        def bind(self, *args, **kwargs):
            pass

        def rowconfigure(self, *args, **kwargs):
            pass

        def columnconfigure(self, *args, **kwargs):
            pass

        def insert(self, *args, **kwargs):
            pass

        def after(self, delay, callback, *args):
            """Immediately invoke callbacks scheduled with 'after'."""
            callback(*args)

        def update_idletasks(self):
            """Stub to mirror tk widget method in tests."""
            pass

    class DummyPanedWindow(DummyWidget):
        def __init__(self, root, **kwargs):
            super().__init__(root, **kwargs)
            self.children = []
            self.sashes = {}

        def add(self, child, **kwargs):
            self.children.append(child)

        def panes(self):
            return self.children

        def sash_place(self, idx, x, y):
            if idx >= len(self.children) - 1:
                raise ValueError("sash index out of range")
            self.sashes[idx] = (x, y)

    fake_tk = types.SimpleNamespace(
        PanedWindow=DummyPanedWindow,
        Frame=DummyWidget,
        Listbox=DummyWidget,
        Text=DummyWidget,
        Button=DummyWidget,
        END="end",
        HORIZONTAL="horizontal",
        BOTH="both",
        GROOVE="groove",
    )

    monkeypatch.setattr(ui, "tk", fake_tk)
    monkeypatch.setattr(ui, "load_pane_layout", lambda file_path=ui.PANE_LAYOUT_FILE: coords)

    class DummyRoot(DummyWidget):
        pass

    cfg = configparser.ConfigParser()
    cfg["ui"] = {}
    root = DummyRoot()

    app = ui.LighthouseApp(root, cfg)

    assert app.top_pane.sashes[0][0] == coords[0]
    assert app.top_pane.sashes[1][0] == coords[1]

