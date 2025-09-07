"""Tests verifying profile buttons are grouped into management and action sections."""

import configparser
from pathlib import Path
import sys
from types import SimpleNamespace

# Ensure application modules are importable when running tests directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    """Load expected group labels from configuration file."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("ui_buttons_config.ini"))
    return cfg


def test_profile_buttons_grouped(monkeypatch) -> None:
    """Profile buttons should be separated into management and action groups."""

    cfg = _load_cfg()
    frame_labels: list[str] = []

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

    class DummyLabelFrame(DummyWidget):
        def __init__(self, master=None, text="", *args, **kwargs):
            super().__init__(*args, **kwargs)
            frame_labels.append(text)

    class DummyButton(DummyWidget):
        def __init__(self, master=None, text="", command=None):
            super().__init__()

    class DummyTreeview(DummyWidget):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.columns = {}

        def heading(self, *args, **kwargs):
            pass

        def column(self, name, width=None, **_):
            if width is not None:
                self.columns[name] = width
            return self.columns.get(name, 0)

        def tag_configure(self, *args, **kwargs):
            pass

    class DummyPanedWindow(DummyWidget):
        def add(self, child, **kwargs):
            pass

    fake_tk = SimpleNamespace(
        PanedWindow=DummyPanedWindow,
        Frame=DummyWidget,
        LabelFrame=DummyLabelFrame,
        Listbox=DummyWidget,
        Text=DummyWidget,
        Button=DummyButton,
        END="end",
        HORIZONTAL="horizontal",
        BOTH="both",
        GROOVE="groove",
    )
    fake_ttk = SimpleNamespace(Treeview=DummyTreeview)

    monkeypatch.setattr(ui, "tk", fake_tk)
    monkeypatch.setattr(ui, "ttk", fake_ttk)
    monkeypatch.setattr(ui, "load_pane_layout", lambda file_path=ui.PANE_LAYOUT_FILE: [])
    monkeypatch.setattr(ui.LighthouseApp, "_setup_logging", lambda self: None)
    monkeypatch.setattr(ui.LighthouseApp, "_load_profiles_into_list", lambda self: None)

    root = DummyWidget()
    ui.LighthouseApp(root, cfg)

    expected_manage = cfg["groups"]["manage_profiles"]
    expected_actions = cfg["groups"]["profile_actions"]

    assert expected_manage in frame_labels
    assert expected_actions in frame_labels

