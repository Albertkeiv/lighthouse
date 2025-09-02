"""Ensure ERROR messages appear in the UI log container."""

import configparser
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import patch

# Make application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    """Load configuration for error logging tests."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("error_log_test_config.ini"))
    return cfg


class DummyLogText:
    """Minimal stand-in for tk.Text capturing output."""

    def __init__(self):
        self.state = "disabled"
        self.content = ""

    def configure(self, **kwargs):
        if "state" in kwargs:
            self.state = kwargs["state"]

    def insert(self, index, text):
        self.content += text

    def see(self, index):  # pragma: no cover - no behaviour required
        pass


def test_error_messages_logged(monkeypatch) -> None:
    cfg = _load_cfg()
    root = object()
    # Only prevent UI construction; allow logging setup
    with patch.object(ui.LighthouseApp, "_build_ui", lambda self: None):
        app = ui.LighthouseApp(root, cfg)
    monkeypatch.setattr(ui, "tk", SimpleNamespace(END="end"))
    app.log_text = DummyLogText()

    message = cfg["logging"]["error_message"]
    app.logger.error(message)

    assert message in app.log_text.content
    assert app.log_text.state == "disabled"
