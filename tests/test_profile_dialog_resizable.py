import configparser
from pathlib import Path
from types import SimpleNamespace
import sys

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _load_cfg():
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profile_dialog_resizable.ini"))
    return cfg


def test_profile_dialog_not_resizable(monkeypatch):
    cfg = _load_cfg()
    expected_width = cfg.getboolean("dialog", "width")
    expected_height = cfg.getboolean("dialog", "height")

    # Minimal tkinter stubs
    class DummyEntry:
        def __init__(self, *a, **k):
            self.value = ""
        def grid(self, *a, **k):
            pass
        def insert(self, index, value):
            self.value = value
        def get(self):
            return self.value
        def configure(self, *a, **k):
            pass

    class DummyLabel:
        def __init__(self, *a, **k):
            pass
        def grid(self, *a, **k):
            pass

    class DummyLabelFrame(DummyLabel):
        def __init__(self, *a, text="", **k):
            super().__init__(*a, **k)
            self._text = text
        def columnconfigure(self, *a, **k):
            pass
        def cget(self, option):
            if option == "text":
                return self._text

    class DummyCombobox:
        def __init__(self, master=None, textvariable=None, state=""):
            self.textvariable = textvariable
            self.values = []
        def grid(self, *a, **k):
            pass
        def __setitem__(self, key, value):
            if key == "values":
                self.values = value

    class DummyCheckbutton:
        def __init__(self, *a, **k):
            pass
        def grid(self, *a, **k):
            pass

    class DummyBooleanVar:
        def __init__(self, value=False):
            self._value = value
        def get(self):
            return self._value
        def set(self, val):
            self._value = val

    class DummyStringVar(DummyBooleanVar):
        pass

    fake_tk = SimpleNamespace(
        Label=DummyLabel,
        LabelFrame=DummyLabelFrame,
        Entry=DummyEntry,
        Checkbutton=DummyCheckbutton,
        BooleanVar=DummyBooleanVar,
        StringVar=DummyStringVar,
        END="end",
    )
    fake_ttk = SimpleNamespace(Combobox=DummyCombobox)

    # Import UI module after patching
    import lighthouse_app.ui as ui

    monkeypatch.setattr(ui, "tk", fake_tk)
    monkeypatch.setattr(ui, "ttk", fake_ttk)

    # Simplified Dialog base class capturing resizable calls
    class DummyDialogBase:
        def __init__(self, parent, title=None):
            self.resizable_width = None
            self.resizable_height = None
            self.tk = True
            self.body(parent)
        def resizable(self, width, height):
            self.resizable_width = width
            self.resizable_height = height
        def cancel(self, event=None):
            pass

    ui.ProfileDialog.__bases__ = (DummyDialogBase,)
    monkeypatch.setattr(ui.KeyController, "load_keys", lambda self: [])

    dialog = ui.ProfileDialog(None, [])

    assert dialog.resizable_width == expected_width
    assert dialog.resizable_height == expected_height
