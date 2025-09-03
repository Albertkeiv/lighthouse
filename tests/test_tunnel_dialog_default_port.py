"""Tests for default SSH port in TunnelDialog."""
import configparser
from pathlib import Path
import logging
from types import SimpleNamespace
import sys

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def test_tunnel_dialog_prefills_ssh_port(monkeypatch) -> None:
    """New tunnel dialog should pre-fill SSH port from config."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profile_tunnels_test_config.ini"))
    expected = cfg["defaults"].getint("ssh_port")

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

    class DummyButton:
        def __init__(self, *_, **__):
            pass
        def grid(self, *_, **__):
            pass
        def configure(self, *_, **__):
            pass

    class DummyFrame:
        def __init__(self, *_, **__):
            pass
        def grid(self, *_, **__):
            pass
        def columnconfigure(self, *_, **__):
            pass

    class DummyLabelFrame(DummyFrame):
        """Behaves like ``DummyFrame`` but records label frames."""
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

    class DummyCheckbutton:
        def __init__(self, *_, **__):
            pass
        def grid(self, *_, **__):
            pass
        def configure(self, *_, **__):
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
            self.logger = logging.getLogger(__name__)

    dialog = DummyDialog()
    dialog.body(object())
    assert dialog.ssh_port_entry.get() == str(expected)

