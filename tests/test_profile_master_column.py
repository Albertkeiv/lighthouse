import configparser
from pathlib import Path
from types import SimpleNamespace
import sys
import logging

# Allow importing the application package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _expected_weight() -> int:
    """Read expected column weight from configuration."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profile_master_column.ini"))
    return cfg.getint("layout", "weight")


def test_profile_dialog_master_expands(monkeypatch) -> None:
    expected = _expected_weight()

    class DummyWidget:
        """Minimal stand-in for Tk widgets."""

        def __init__(self, *args, **kwargs):
            self.column_weights = {}

        def grid(self, *args, **kwargs):
            pass

        def pack(self, *args, **kwargs):
            pass

        def columnconfigure(self, index, weight=0, **kwargs):
            self.column_weights[index] = weight

        def rowconfigure(self, *args, **kwargs):
            pass

        def insert(self, *args, **kwargs):
            pass

        def configure(self, *args, **kwargs):
            pass

    class DummyLabelFrame(DummyWidget):
        def __init__(self, *args, text="", **kwargs):
            super().__init__(*args, **kwargs)
            self._text = text

    class DummyEntry(DummyWidget):
        pass

    class DummyCombo(DummyWidget):
        def __init__(self, *_, textvariable=None, state=None, **__):
            super().__init__()
            self._values = []

        def __setitem__(self, key, value):
            if key == "values":
                self._values = value

    class DummyVar:
        def __init__(self, value=None):
            self._value = value

        def get(self):
            return self._value

        def set(self, value):
            self._value = value

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

    dialog = ui.ProfileDialog.__new__(ui.ProfileDialog)
    dialog.logger = logging.getLogger("test")
    dialog.profile = None
    dialog.existing_profiles = []

    master = DummyWidget()
    dialog.body(master)

    assert master.column_weights.get(0) == expected
    assert master.column_weights.get(1) == expected

