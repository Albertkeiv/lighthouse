"""Ensure private keys load when Paramiko lacks DSSKey."""

import configparser
from pathlib import Path
import sys

# Make application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    """Load expectations for read_private_key_without_dsskey tests."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("read_private_key_without_dsskey_test_config.ini"))
    return cfg


def test_read_private_key_file_handles_missing_dsskey(tmp_path, monkeypatch) -> None:
    cfg = _load_cfg()
    monkeypatch.delattr(ui.paramiko, "DSSKey", raising=False)
    bits = cfg["generate"].getint("bits")
    key_file = tmp_path / "id_rsa"
    key = ui.paramiko.RSAKey.generate(bits)
    key.write_private_key_file(str(key_file))
    loaded = ui.SSHTunnelForwarder.read_private_key_file(
        pkey_file=str(key_file), logger=None
    )
    expected_class = getattr(ui.paramiko, cfg["expected"]["class"])
    assert isinstance(loaded, expected_class)
    assert loaded.get_bits() == cfg["expected"].getint("bits")
