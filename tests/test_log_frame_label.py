"""Ensure log output is wrapped in a labelled frame."""

import configparser
from pathlib import Path
import sys
from types import SimpleNamespace

# Allow importing the application
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _expected_label() -> str:
    """Read expected log label from configuration."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("log_label.ini"))
    return cfg["label"]["log"]


def test_log_frame_has_label(monkeypatch) -> None:
    """Log frame should be labelled according to configuration."""
    expected = _expected_label()

    class DummyWidget:
        """Minimal stand-in for Tk widgets."""
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

    class DummyLabelFrame(DummyWidget):
        def __init__(self, *_, text="", **__):
            super().__init__()
            self._text = text
        def cget(self, option):
            if option == "text":
                return self._text

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
        def tag_configure(self, *args, **kwargs):
            pass

    fake_tk = SimpleNamespace(
        PanedWindow=DummyPanedWindow,
        Frame=DummyWidget,
        LabelFrame=DummyLabelFrame,
        Listbox=DummyWidget,
        Text=DummyWidget,
        Button=DummyWidget,
        END="end",
        HORIZONTAL="horizontal",
        BOTH="both",
        GROOVE="groove",
    )
    fake_ttk = SimpleNamespace(Treeview=DummyTreeview)

    monkeypatch.setattr(ui, "tk", fake_tk)
    monkeypatch.setattr(ui, "ttk", fake_ttk)
    monkeypatch.setattr(ui.LighthouseApp, "_setup_logging", lambda self: None)
    monkeypatch.setattr(ui.LighthouseApp, "_load_profiles_into_list", lambda self: None)
    monkeypatch.setattr(ui, "load_pane_layout", lambda file_path=ui.PANE_LAYOUT_FILE: [])

    cfg = configparser.ConfigParser()
    cfg["ui"] = {}
    root = DummyWidget()

    app = ui.LighthouseApp(root, cfg)

    assert app.log_frame.cget("text") == expected
