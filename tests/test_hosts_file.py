"""Tests for the hosts file constant used by the application."""

import configparser
from pathlib import Path
import sys

# Ensure the application package is importable during tests
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app.hosts import HOSTS_FILE


def _load_cfg() -> configparser.ConfigParser:
    """Load expected host paths from configuration."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("hosts_path_test_config.ini"))
    return cfg


def test_hosts_file_constant():
    cfg = _load_cfg()
    assert str(HOSTS_FILE) == cfg["hosts"]["windows"]
