import configparser
from pathlib import Path
import logging
from types import SimpleNamespace
import sys

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def test_tunnel_dialog_labelframes(monkeypatch) -> None:
    """Tunnel dialog should group fields into expected label frames."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profile_tunnels_test_config.ini"))

    created_frames = []
    created_labels = []

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
        def __init__(self, master=None, text=""):
            created_labels.append(text)
        def grid(self, *_, **__):
            pass

    class DummyButton:
        def __init__(self, *_, **__):
            pass
        def grid(self, *_, **__):
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
            created_frames.append(text)

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

    fake_tk = SimpleNamespace(
        Label=DummyLabel,
        Entry=DummyEntry,
        Button=DummyButton,
        Frame=DummyFrame,
        LabelFrame=DummyLabelFrame,
        Listbox=DummyListbox,
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

    expected_frames = [
        cfg["ui_labels"]["tunnel_name"],
        cfg["ui_labels"]["ssh_settings"],
        cfg["ui_labels"]["tunnel_settings"],
        cfg["ui_labels"]["dns_override"],
    ]
    assert created_frames == expected_frames
    assert cfg["ui_labels"]["dns_name"] in created_labels
