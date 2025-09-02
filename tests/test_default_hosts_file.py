"""Tests for resolving platform specific hosts file paths."""

import configparser
from pathlib import Path
import platform
import sys

# Ensure the application package is importable during tests
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app.hosts import default_hosts_file


def _load_cfg() -> configparser.ConfigParser:
    """Load expected host paths from configuration."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("hosts_path_test_config.ini"))
    return cfg


def test_default_hosts_file_linux(monkeypatch):
    cfg = _load_cfg()
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    assert str(default_hosts_file()) == cfg["hosts"]["linux"]


def test_default_hosts_file_windows(monkeypatch):
    cfg = _load_cfg()
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    assert str(default_hosts_file()) == cfg["hosts"]["windows"]
