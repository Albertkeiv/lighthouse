import configparser
from pathlib import Path
import logging
from types import SimpleNamespace
import sys

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def test_tunnel_dialog_enforces_geometry_after_buttons(monkeypatch) -> None:
    """Geometry should account for buttons added after the body."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("dialog_minsize.ini"))
    expected_w = cfg["tunnel"].getint("width")
    expected_h = cfg["tunnel"].getint("height")
    initial_h = expected_h - 40

    class DummyEntry:
        def __init__(self, master=None):
            self.value = ""
        def grid(self, *_, **__):
            pass
        def insert(self, index, value):
            self.value = value
        def get(self):
            return self.value
        def configure(self, *_, **__):
            pass

    class DummyLabel:
        def __init__(self, *_, **__):
            pass
        def grid(self, *_, **__):
            pass
        def configure(self, *_, **__):
            pass

    class DummyButton(DummyLabel):
        pass

    class DummyFrame:
        def __init__(self, *_, **__):
            pass
        def grid(self, *_, **__):
            pass
        def columnconfigure(self, *_, **__):
            pass

    class DummyLabelFrame(DummyFrame):
        def __init__(self, master=None, text=""):
            super().__init__(master)
            self.text = text

    class DummyListbox:
        def __init__(self, *_, **__):
            self.items = []
        def grid(self, *_, **__):
            pass
        def insert(self, index, value):
            self.items.append(value)
        def get(self, start, end):
            return self.items
        def delete(self, start, end=None):
            self.items.clear()
        def configure(self, *_, **__):
            pass

    class DummyCheckbutton(DummyLabel):
        pass

    class DummyVar:
        def __init__(self, value=True):
            self.value = value
        def get(self):
            return self.value
        def set(self, value):
            self.value = value

    fake_tk = SimpleNamespace(
        Label=DummyLabel,
        Entry=DummyEntry,
        Button=DummyButton,
        Frame=DummyFrame,
        LabelFrame=DummyLabelFrame,
        Listbox=DummyListbox,
        Checkbutton=DummyCheckbutton,
        BooleanVar=DummyVar,
        NORMAL="normal",
        DISABLED="disabled",
        END="end",
    )
    monkeypatch.setattr(ui, "tk", fake_tk)

    class DummyDialog(ui.TunnelDialog):
        def __init__(self):
            self.existing_tunnels = []
            self.tunnel = None
            self.dns_names = []
            self.logger = logging.getLogger("test")
            self.geometry_called = None
            self.minsize_called = None
            self.after_func = None
            self.req_h = initial_h
            class _Tk:
                def createcommand(self, name, func):
                    return name
            self.tk = _Tk()
        def resizable(self, *_, **__):
            pass
        def update_idletasks(self):
            pass
        def winfo_width(self):
            return expected_w - 20
        def winfo_height(self):
            return self.req_h - 20
        def winfo_reqwidth(self):
            return expected_w
        def winfo_reqheight(self):
            return self.req_h
        def geometry(self, value):
            self.geometry_called = value
        def minsize(self, w, h):
            self.minsize_called = (w, h)
        def after(self, delay, func):
            self.after_func = func
        def _toggle_dns_widgets(self):
            pass

    dialog = DummyDialog()
    dialog.body(object())
    # simulate buttonbox increasing required height
    dialog.req_h = expected_h
    dialog.after_func()

    assert dialog.geometry_called == f"{expected_w}x{expected_h}"
    assert dialog.minsize_called == (expected_w, expected_h)
