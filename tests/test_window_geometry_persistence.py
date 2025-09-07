import configparser
from pathlib import Path
import sys

# Allow application import
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def test_window_geometry_persisted(tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.ini"
    cfg = configparser.ConfigParser()
    cfg["ui"] = {"width": "800", "height": "600"}
    cfg_path.write_text("[ui]\nwidth=800\nheight=600\n", encoding="utf-8")

    monkeypatch.setattr(ui, "CONFIG_FILE", cfg_path)
    monkeypatch.setattr(ui.LighthouseApp, "_build_ui", lambda self: None)

    class DummyRoot:
        def __init__(self):
            self.protocol_handler = None
        def protocol(self, name, func):
            self.protocol_handler = func
        def winfo_width(self):
            return 1024
        def winfo_height(self):
            return 768
        def destroy(self):
            self.destroy_called = True

    monkeypatch.setattr(ui.LighthouseApp, "_setup_logging", lambda self: None)
    root = DummyRoot()
    app = ui.LighthouseApp(root, cfg)

    # Simulate window close
    app._on_close()

    saved = configparser.ConfigParser()
    saved.read(cfg_path)
    assert saved.getint("ui", "width") == 1024
    assert saved.getint("ui", "height") == 768
