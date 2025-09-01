"""Tests for UI profile name validation."""
import configparser
from pathlib import Path
import sys
from unittest.mock import patch


# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app.ui import LighthouseApp


def _load_cfg() -> configparser.ConfigParser:
    """Load configuration values used for tests."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profiles_test_config.ini"))
    return cfg


def test_duplicate_profile_name_checked_immediately() -> None:
    """Profile name should be validated before asking for other data."""
    cfg = _load_cfg()
    existing_name = cfg["profile1"]["name"]

    # Minimal root object; UI construction and logging are patched out.
    root = object()
    with patch.object(LighthouseApp, "_setup_logging", lambda self: None), \
         patch.object(LighthouseApp, "_build_ui", lambda self: None):
        app = LighthouseApp(root, cfg)

    with patch("lighthouse_app.ui.load_profiles", return_value=[{"name": existing_name}]) as mock_load, \
         patch("lighthouse_app.ui.create_profile") as mock_create, \
         patch("lighthouse_app.ui.simpledialog.askstring", side_effect=[existing_name]) as mock_ask, \
         patch("lighthouse_app.ui.messagebox.showerror") as mock_error:
        app._on_new_profile()

    mock_load.assert_called_once()
    mock_ask.assert_called_once()
    mock_error.assert_called_once_with("Error", f"Profile '{existing_name}' already exists")
    mock_create.assert_not_called()

