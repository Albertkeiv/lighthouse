"""Tests ensuring tunnel list columns stay within container width."""
import configparser
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

# Allow importing the application
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    """Load configuration for tunnel list sizing tests."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("tunnel_columns.ini"))
    return cfg


def test_tunnel_list_columns_fit_container() -> None:
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
    app.tunnel_list = DummyTreeview()

    total_width = cfg.getint("tunnel_list", "total_width")
    event = SimpleNamespace(width=total_width)
    app._on_tunnel_list_configure(event)

    name_ratio = cfg.getfloat("tunnel_list", "name_ratio")
    target_ratio = cfg.getfloat("tunnel_list", "target_ratio")
    expected_name = int(total_width * name_ratio)
    expected_target = int(total_width * target_ratio)

    assert app.tunnel_list.widths["name"] == expected_name
    assert app.tunnel_list.widths["target"] == expected_target
    assert app.tunnel_list.widths["name"] + app.tunnel_list.widths["target"] == total_width
