"""Tests for tunnel list double-click behaviour."""
import configparser
from pathlib import Path
import sys
from types import SimpleNamespace

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    """Load configuration for tunnel list events."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("tunnel_list_events.ini"))
    return cfg


def test_tunnel_list_double_click_triggers_edit(monkeypatch) -> None:
    """Double-clicking a tunnel should invoke the edit handler."""
    cfg = _load_cfg()

    class DummyTreeview:
        def __init__(self, *_, **__):
            self.bindings = {}
        def pack(self, *_, **__):
            pass
        def bind(self, event, callback):
            self.bindings[event] = callback
        def heading(self, *_, **__):
            pass
        def column(self, *_, **__):
            return 0
        def selection(self):
            return ()
        def item(self, *_, **__):
            return ()
        def tag_configure(self, *args, **kwargs):
            pass

    class DummyWidget:
        def __init__(self, *_, **__):
            pass
        def grid(self, *_, **__):
            pass
        def pack(self, *_, **__):
            pass
        def bind(self, *_, **__):
            pass
        def rowconfigure(self, *_, **__):
            pass
        def columnconfigure(self, *_, **__):
            pass
        def insert(self, *_, **__):
            pass
        def after(self, delay, callback, *args):
            callback(*args)
        def update_idletasks(self):
            pass

    class DummyPanedWindow(DummyWidget):
        def add(self, child, **kwargs):
            pass
        def panes(self):
            return []
        def sash_coord(self, idx):
            return (0, 0)
        def sash_place(self, idx, x, y):
            pass

    class DummyButton(DummyWidget):
        pass

    fake_tk = SimpleNamespace(
        PanedWindow=DummyPanedWindow,
        Frame=DummyWidget,
        Listbox=DummyWidget,
        Text=DummyWidget,
        Button=DummyButton,
        END="end",
        HORIZONTAL="horizontal",
        BOTH="both",
        GROOVE="groove",
    )

    fake_ttk = SimpleNamespace(Treeview=DummyTreeview)
    monkeypatch.setattr(ui, "tk", fake_tk)
    monkeypatch.setattr(ui, "ttk", fake_ttk)
    monkeypatch.setattr(ui, "load_pane_layout", lambda file_path=ui.PANE_LAYOUT_FILE: [])
    monkeypatch.setattr(ui.LighthouseApp, "_setup_logging", lambda self: None)
    monkeypatch.setattr(ui.LighthouseApp, "_load_profiles_into_list", lambda self: None)

    root = DummyWidget()
    app = ui.LighthouseApp(root, cfg)

    calls = []
    app._on_edit_tunnel = lambda: calls.append(True)

    event_name = cfg["events"]["double_click"]
    assert event_name in app.tunnel_list.bindings
    app.tunnel_list.bindings[event_name](None)
    assert calls
