"""Ensure tunnel setup works when Paramiko lacks DSSKey."""

import configparser
from pathlib import Path
import sys

# Make application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    """Load expectations for DSSKey absence test."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("get_keys_without_dsskey_test_config.ini"))
    return cfg


def test_get_keys_handles_missing_dsskey(monkeypatch) -> None:
    cfg = _load_cfg()
    monkeypatch.delattr(ui.paramiko, "DSSKey", raising=False)
    keys = ui.SSHTunnelForwarder.get_keys(
        logger=None, host_pkey_directories=[], allow_agent=False
    )
    assert len(keys) == cfg["expected"].getint("key_count")
