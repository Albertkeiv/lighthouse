"""Ensure the info/log pane stretches with the window width."""

import configparser
from pathlib import Path
import types
import sys

# Make application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _expected_weight() -> int:
    """Read expected column weight from configuration file."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("info_pane_layout.ini"))
    return cfg.getint("layout", "info_frame_column_weight")


def test_info_frame_expands_with_window(monkeypatch):
    expected_weight = _expected_weight()

    class DummyWidget:
        """Minimal stand-in for Tk widgets used in tests."""
        def __init__(self, *args, **kwargs):
            self.column_weights = {}
            self.row_weights = {}

        def grid(self, *args, **kwargs):
            pass

        def pack(self, *args, **kwargs):
            pass

        def bind(self, *args, **kwargs):
            pass

        def rowconfigure(self, index, weight=0, **kwargs):
            self.row_weights[index] = weight

        def columnconfigure(self, index, weight=0, **kwargs):
            self.column_weights[index] = weight

        def insert(self, *args, **kwargs):
            pass

        def after(self, delay, callback, *args):
            callback(*args)

        def update_idletasks(self):
            pass

    class DummyPanedWindow(DummyWidget):
        def __init__(self, root, **kwargs):
            super().__init__(root, **kwargs)
            self.children = []

        def add(self, child, **kwargs):
            self.children.append(child)

        def panes(self):
            return self.children

    class DummyTreeview(DummyWidget):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.columns = {}

        def heading(self, *_, **__):
            pass

        def column(self, name, width=None, **_):
            if width is not None:
                self.columns[name] = width
            return self.columns.get(name, 0)

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
    fake_ttk = types.SimpleNamespace(Treeview=DummyTreeview)

    monkeypatch.setattr(ui, "tk", fake_tk)
    monkeypatch.setattr(ui, "ttk", fake_ttk)
    monkeypatch.setattr(ui.LighthouseApp, "_setup_logging", lambda self: None)

    cfg = configparser.ConfigParser()
    cfg["ui"] = {}
    root = DummyWidget()

    app = ui.LighthouseApp(root, cfg)

    info_frame = app.top_pane.children[2]
    assert info_frame.column_weights.get(0) == expected_weight
