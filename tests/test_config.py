"""Tests verifying configuration values for the UI."""
import configparser
import sys
from pathlib import Path

# Ensure the application package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def load_cfg():
    cfg = configparser.ConfigParser()
    cfg.read('config.ini')
    return cfg


def test_geometry_matches_config():
    cfg = load_cfg()
    expected = f"{cfg.getint('ui', 'width')}x{cfg.getint('ui', 'height')}"
    assert ui.geometry_from_config(cfg) == expected


def test_config_contains_required_fields():
    cfg = load_cfg()
    assert cfg.has_section('ui'), "Missing 'ui' section in config.ini"
    assert cfg.get('ui', 'title'), "UI title must be set"
