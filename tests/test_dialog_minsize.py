import configparser
from pathlib import Path
from types import SimpleNamespace
import sys
import logging

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _expected_sizes():
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("dialog_minsize.ini"))
    return {
        "profile": (
            cfg.getint("profile", "width"),
            cfg.getint("profile", "height"),
        ),
        "tunnel": (
            cfg.getint("tunnel", "width"),
            cfg.getint("tunnel", "height"),
        ),
    }


def test_profile_dialog_sets_minsize(monkeypatch) -> None:
    sizes = _expected_sizes()
    expected_w, expected_h = sizes["profile"]

    class DummyWidget:
        def __init__(self, *a, **k):
            pass
        def grid(self, *a, **k):
            pass
        def pack(self, *a, **k):
            pass
        def columnconfigure(self, *a, **k):
            pass
        def rowconfigure(self, *a, **k):
            pass
        def insert(self, *a, **k):
            pass
        def configure(self, *a, **k):
            pass

    class DummyLabelFrame(DummyWidget):
        def __init__(self, *a, text="", **k):
            super().__init__(*a, **k)

    class DummyEntry(DummyWidget):
        pass

    class DummyCombo(DummyWidget):
        def __init__(self, *a, textvariable=None, state=None, **k):
            super().__init__(*a, **k)
            self.values = []
        def __setitem__(self, key, value):
            if key == "values":
                self.values = value

    class DummyVar:
        def __init__(self, value=None):
            self.value = value
        def get(self):
            return self.value
        def set(self, v):
            self.value = v

    fake_tk = SimpleNamespace(
        LabelFrame=DummyLabelFrame,
        Entry=DummyEntry,
        Label=DummyWidget,
        BooleanVar=DummyVar,
        Checkbutton=DummyWidget,
        StringVar=DummyVar,
    )
    fake_ttk = SimpleNamespace(Combobox=DummyCombo)

    monkeypatch.setattr(ui, "tk", fake_tk)
    monkeypatch.setattr(ui, "ttk", fake_ttk)
    monkeypatch.setattr(ui.ProfileDialog, "_load_key_map", staticmethod(lambda: {}))

    class DummyDialog(ui.ProfileDialog):
        def __init__(self):
            self.logger = logging.getLogger("test")
            self.profile = None
            self.existing_profiles = []
            self.minsize_called = None
            self.tk = True

        def resizable(self, *a, **k):
            pass

        def update_idletasks(self):
            pass

        def winfo_reqwidth(self):
            return expected_w

        def winfo_reqheight(self):
            return expected_h

        def minsize(self, w, h):
            self.minsize_called = (w, h)

    dialog = DummyDialog()
    dialog.body(DummyWidget())

    assert dialog.minsize_called == (expected_w, expected_h)


def test_tunnel_dialog_sets_minsize(monkeypatch) -> None:
    sizes = _expected_sizes()
    expected_w, expected_h = sizes["tunnel"]

    class DummyWidget:
        def __init__(self, *a, **k):
            pass
        def grid(self, *a, **k):
            pass
        def pack(self, *a, **k):
            pass
        def columnconfigure(self, *a, **k):
            pass
        def rowconfigure(self, *a, **k):
            pass
        def insert(self, *a, **k):
            pass
        def configure(self, *a, **k):
            pass

    class DummyLabel(DummyWidget):
        pass

    class DummyEntry(DummyWidget):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.value = ""
        def get(self):
            return self.value
        def insert(self, i, v):
            self.value = v

    class DummyButton(DummyWidget):
        pass

    class DummyFrame(DummyWidget):
        pass

    class DummyLabelFrame(DummyFrame):
        def __init__(self, *a, text="", **k):
            super().__init__(*a, **k)

    class DummyListbox(DummyWidget):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.items = []
        def insert(self, i, v):
            self.items.append(v)
        def get(self, a, b):
            return self.items
        def delete(self, *a, **k):
            self.items.clear()

    class DummyCheckbutton(DummyWidget):
        pass

    class DummyVar:
        def __init__(self, value=True):
            self.value = value
        def get(self):
            return self.value
        def set(self, v):
            self.value = v

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
            self.minsize_called = None
            self.geometry_called = None
            self.tk = True

        def resizable(self, *a, **k):
            pass

        def update_idletasks(self):
            pass

        def winfo_width(self):
            return expected_w - 40

        def winfo_height(self):
            return expected_h - 40

        def winfo_reqwidth(self):
            return expected_w

        def winfo_reqheight(self):
            return expected_h

        def geometry(self, value):
            self.geometry_called = value

        def minsize(self, w, h):
            self.minsize_called = (w, h)

        def _toggle_dns_widgets(self):
            pass

    dialog = DummyDialog()
    dialog.body(object())

    assert dialog.minsize_called == (expected_w, expected_h)
    assert dialog.geometry_called == f"{expected_w}x{expected_h}"

