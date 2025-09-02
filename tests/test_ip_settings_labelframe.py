"""Ensure IP options in profile dialog are grouped in a labelled frame."""

import configparser
from pathlib import Path
import sys
from types import SimpleNamespace
import logging

# Allow importing the application
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _expected_label() -> str:
    """Read expected IP settings label from configuration."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("ip_settings_label.ini"))
    return cfg["label"]["ip_settings"]


def test_ip_settings_uses_labelframe(monkeypatch) -> None:
    """Profile dialog should wrap IP options in a labelled frame."""
    expected = _expected_label()

    class DummyWidget:
        """Minimal stand-in for Tk widgets."""

        def __init__(self, *_, **__):
            pass

        def grid(self, *_, **__):
            pass

        def pack(self, *_, **__):
            pass

        def rowconfigure(self, *_, **__):
            pass

        def columnconfigure(self, *_, **__):
            pass

        def insert(self, *_, **__):
            pass

        def configure(self, *_, **__):
            pass

    class DummyLabelFrame(DummyWidget):
        def __init__(self, *_, text="", **__):
            super().__init__()
            self._text = text

        def cget(self, option):
            if option == "text":
                return self._text

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
    dialog.existing_profiles = []
    dialog.profile = None
    dialog.logger = logging.getLogger("test")

    master = DummyWidget()
    dialog.body(master)

    assert isinstance(dialog.ip_frame, DummyLabelFrame)
    assert dialog.ip_frame.cget("text") == expected

