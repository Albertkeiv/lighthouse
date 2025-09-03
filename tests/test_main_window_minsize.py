import configparser
from pathlib import Path
from types import SimpleNamespace
import sys

# Allow application import
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _expected_size():
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("window_minsize.ini"))
    return cfg.getint("size", "width"), cfg.getint("size", "height")


def test_main_window_minsize(monkeypatch):
    expected_w, expected_h = _expected_size()

    class DummyRoot:
        def __init__(self):
            self.minsize_called = None
            self.geometry_called = None

        def columnconfigure(self, *a, **k):
            pass

        def rowconfigure(self, *a, **k):
            pass

        def bind(self, *a, **k):
            pass

        def after(self, *a, **k):
            pass

        def update_idletasks(self):
            pass

        def winfo_reqwidth(self):
            return expected_w

        def winfo_reqheight(self):
            return expected_h

        def winfo_width(self):
            return expected_w - 50

        def winfo_height(self):
            return expected_h - 50

        def geometry(self, value):
            self.geometry_called = value

        def minsize(self, w, h):
            self.minsize_called = (w, h)

    class DummyWidget:
        def __init__(self, *a, **k):
            self.children = []
            self.column_weights = {}
            self.row_weights = {}

        def grid(self, *a, **k):
            pass

        def pack(self, *a, **k):
            pass

        def columnconfigure(self, index, weight=0, **k):
            self.column_weights[index] = weight

        def rowconfigure(self, index, weight=0, **k):
            self.row_weights[index] = weight

        def bind(self, *a, **k):
            pass

        def add(self, child, **k):
            self.children.append(child)

        def panes(self):
            return self.children

    class DummyPanedWindow(DummyWidget):
        pass

    class DummyTreeview(DummyWidget):
        def heading(self, *a, **k):
            pass

        def column(self, *a, **k):
            return 0

        def tag_configure(self, *a, **k):
            pass

    fake_tk = SimpleNamespace(
        PanedWindow=DummyPanedWindow,
        Frame=DummyWidget,
        LabelFrame=DummyWidget,
        Text=DummyWidget,
        Button=DummyWidget,
        BOTH="both",
        HORIZONTAL="horizontal",
        GROOVE="groove",
        END="end",
    )
    fake_ttk = SimpleNamespace(Treeview=DummyTreeview)

    class DummyProfileController:
        def __init__(self, *a, **k):
            self.active_tunnels = {}
        def load_profiles(self):
            return []

    class DummyKeyController:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(ui, "tk", fake_tk)
    monkeypatch.setattr(ui, "ttk", fake_ttk)
    monkeypatch.setattr(ui, "ProfileController", DummyProfileController)
    monkeypatch.setattr(ui, "KeyController", DummyKeyController)
    monkeypatch.setattr(ui.LighthouseApp, "_setup_logging", lambda self: None)
    monkeypatch.setattr(ui.LighthouseApp, "_load_profiles_into_list", lambda self: None)

    cfg = configparser.ConfigParser()
    cfg["ui"] = {}
    root = DummyRoot()
    ui.LighthouseApp(root, cfg)

    assert root.minsize_called == (expected_w, expected_h)

