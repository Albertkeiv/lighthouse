"""Tests for the hosts file constant used by the application."""

import configparser
from pathlib import Path
import sys

# Ensure the application package is importable during tests
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app.hosts import HOSTS_FILE

CFG_PATH = Path(__file__).with_name("hosts_path_test_config.ini")


def test_default_hosts_file_windows() -> None:
    """Ensure HOSTS_FILE uses the expected Windows path."""
    cfg = configparser.ConfigParser()
    cfg.read(CFG_PATH)
    expected_path = Path(cfg["hosts"]["windows"])
    assert HOSTS_FILE == expected_path
