"""Tests for presence and labels of buttons."""
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


def test_buttons_labels(monkeypatch) -> None:
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

    class DummyTreeview(DummyWidget):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.columns = {}

        def heading(self, *_, **__):
            pass

        def column(self, name, width=None, **_):
            if width is not None:
                self.columns[name] = width
            return self.columns.get(name, 0)

        def tag_configure(self, *args, **kwargs):
            pass

    fake_tk = SimpleNamespace(
        PanedWindow=DummyPanedWindow,
        Frame=DummyWidget,
        LabelFrame=DummyWidget,
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

    expected_settings = cfg["buttons"]["settings"]
    expected_manage = cfg["buttons"]["manage_ssh_key"]
    expected_edit = cfg["buttons"]["edit_profile"]
    expected_start_profile = cfg["buttons"]["start_profile"]
    expected_stop_profile = cfg["buttons"]["stop_profile"]
    expected_new_tunnel = cfg["buttons"]["new_tunnel"]
    expected_edit_tunnel = cfg["buttons"]["edit_tunnel"]
    expected_delete_tunnel = cfg["buttons"]["delete_tunnel"]
    expected_start_tunnel = cfg["buttons"]["start_tunnel"]
    expected_stop_tunnel = cfg["buttons"]["stop_tunnel"]

    assert expected_settings in labels
    assert expected_manage in labels
    assert expected_edit in labels
    assert expected_start_profile in labels
    assert expected_stop_profile in labels
    assert expected_new_tunnel in labels
    assert expected_edit_tunnel in labels
    assert expected_delete_tunnel in labels
    assert expected_start_tunnel in labels
    assert expected_stop_tunnel in labels
