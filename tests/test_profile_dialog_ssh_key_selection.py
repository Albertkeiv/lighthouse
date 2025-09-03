import configparser
from pathlib import Path
from types import SimpleNamespace
import sys

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _load_cfgs():
    cfg_profiles = configparser.ConfigParser()
    cfg_profiles.read(Path(__file__).with_name("profiles_test_config.ini"))
    cfg_keys = configparser.ConfigParser()
    cfg_keys.read(Path(__file__).with_name("ssh_keys_test_config.ini"))
    return cfg_profiles, cfg_keys


def test_profile_dialog_uses_existing_keys(monkeypatch):
    cfg_profiles, cfg_keys = _load_cfgs()

    key_name = cfg_keys["key1"]["name"]
    key_path = cfg_keys["key1"]["filename"]

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
        def get(self):
            return self.textvariable.get()

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

    # Simplified Dialog base class
    class DummyDialogBase:
        def __init__(self, parent, title=None):
            self.result = None
            self.parent = parent
            self.body(parent)

        def cancel(self, event=None):
            pass

    ui.ProfileDialog.__bases__ = (DummyDialogBase,)
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(
        ui.KeyController,
        "load_keys",
        lambda self: [{"name": key_name, "path": key_path}],
    )

    dialog = ui.ProfileDialog(None, [])
    profile_name = cfg_profiles["profile1"]["name"]
    dialog.name_entry.insert(0, profile_name)
    dialog.key_var.set(key_name)

    assert dialog.validate()
    dialog.apply()

    assert dialog.result == (profile_name, key_path, None, True)
