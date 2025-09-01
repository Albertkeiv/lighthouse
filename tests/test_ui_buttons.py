"""Tests for presence and labels of bottom action buttons."""
import configparser
from pathlib import Path
import sys
from types import SimpleNamespace

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    """Load expected button labels from configuration."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("ui_buttons_config.ini"))
    return cfg


def test_bottom_buttons_labels(monkeypatch) -> None:
    """Buttons should have labels defined in configuration file."""
    cfg = _load_cfg()
    labels = []

    class DummyButton:
        def __init__(self, master=None, text="", command=None):
            labels.append(text)

        def grid(self, *args, **kwargs):
            pass

        def pack(self, *args, **kwargs):
            pass

    class DummyWidget:
        def __init__(self, *args, **kwargs):
            pass

        def grid(self, *args, **kwargs):
            pass

        def pack(self, *args, **kwargs):
            pass

        def bind(self, *args, **kwargs):
            pass

        def rowconfigure(self, *args, **kwargs):
            pass

        def columnconfigure(self, *args, **kwargs):
            pass

        def insert(self, *args, **kwargs):
            pass

        def after(self, delay, callback, *args):
            callback(*args)

        def update_idletasks(self):
            pass

    class DummyPanedWindow(DummyWidget):
        def add(self, child, **kwargs):
            pass

    fake_tk = SimpleNamespace(
        PanedWindow=DummyPanedWindow,
        Frame=DummyWidget,
        Listbox=DummyWidget,
        Text=DummyWidget,
        Button=DummyButton,
        END="end",
        HORIZONTAL="horizontal",
        BOTH="both",
        GROOVE="groove",
    )

    monkeypatch.setattr(ui, "tk", fake_tk)
    monkeypatch.setattr(ui, "load_pane_layout", lambda file_path=ui.PANE_LAYOUT_FILE: [])
    monkeypatch.setattr(ui.LighthouseApp, "_setup_logging", lambda self: None)
    monkeypatch.setattr(ui.LighthouseApp, "_load_profiles_into_list", lambda self: None)

    root = DummyWidget()
    ui.LighthouseApp(root, cfg)

    expected_settings = cfg["buttons"]["settings"]
    expected_manage = cfg["buttons"]["manage_ssh_key"]

    assert expected_settings in labels
    assert expected_manage in labels
