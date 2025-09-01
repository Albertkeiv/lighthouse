"""Tests ensuring profile list columns stay within container width."""
import configparser
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

# Allow importing the application
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    """Load configuration for profile list sizing tests."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profile_columns.ini"))
    return cfg


def test_profile_list_columns_fit_container() -> None:
    """Columns should match container width based on predefined ratios."""
    cfg = _load_cfg()
    root = object()
    with patch.object(ui.LighthouseApp, "_setup_logging", lambda self: None), \
         patch.object(ui.LighthouseApp, "_build_ui", lambda self: None):
        app = ui.LighthouseApp(root, cfg)

    class DummyTreeview:
        def __init__(self):
            self.widths = {}
        def column(self, col, width=None, **_):
            if width is not None:
                self.widths[col] = width
            return self.widths.get(col, 0)
    app.profile_list = DummyTreeview()

    total_width = cfg.getint("profile_list", "total_width")
    event = SimpleNamespace(width=total_width)
    app._on_profile_list_configure(event)

    name_ratio = cfg.getfloat("profile_list", "name_ratio")
    ip_ratio = cfg.getfloat("profile_list", "ip_ratio")
    expected_name = int(total_width * name_ratio)
    expected_ip = int(total_width * ip_ratio)

    assert app.profile_list.widths["name"] == expected_name
    assert app.profile_list.widths["ip"] == expected_ip
    assert app.profile_list.widths["name"] + app.profile_list.widths["ip"] == total_width
