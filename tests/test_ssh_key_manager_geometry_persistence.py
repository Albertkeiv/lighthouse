import configparser
from pathlib import Path
from types import SimpleNamespace
import sys

# Allow application import
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def test_ssh_key_manager_geometry_persisted(tmp_path, monkeypatch):
    """Window size should be restored from and saved to config."""
    cfg_path = tmp_path / "config.ini"
    cfg_path.write_text("[ssh_key_manager]\nwidth=450\nheight=350\n", encoding="utf-8")

    monkeypatch.setattr(ui, "CONFIG_FILE", cfg_path)

    geometry_calls = []

    class DummyTreeview:
        def __init__(self, *_, **__):
            pass
        def heading(self, *_, **__):
            pass
        def pack(self, *_, **__):
            pass
        def insert(self, *_, **__):
            pass
        def bind(self, *_, **__):
            pass

    class DummyButton:
        def __init__(self, *_, **__):
            pass
        def pack(self, *_, **__):
            pass

    class DummyToplevel:
        def __init__(self, *_, **__):
            self._width = 450
            self._height = 350
        def title(self, *_, **__):
            pass
        def geometry(self, value):
            geometry_calls.append(value)
        def winfo_width(self):
            return self._width
        def winfo_height(self):
            return self._height
        def protocol(self, name, func):
            self.protocol_func = func
        def destroy(self):
            self.destroyed = True

    fake_tk = SimpleNamespace(
        Toplevel=DummyToplevel,
        Button=DummyButton,
        BOTH="both",
        END="end",
    )
    fake_ttk = SimpleNamespace(Treeview=DummyTreeview)

    monkeypatch.setattr(ui, "tk", fake_tk)
    monkeypatch.setattr(ui, "ttk", fake_ttk)

    controller = ui.KeyController()
    monkeypatch.setattr(controller, "load_keys", lambda: [])

    # Initial load should use size from config
    manager = ui.SSHKeyManager(None, controller)
    assert "450x350" in geometry_calls

    # Simulate resize and close
    manager.top._width = 500
    manager.top._height = 400
    manager._on_close()

    saved = configparser.ConfigParser()
    saved.read(cfg_path)
    assert saved.getint("ssh_key_manager", "width") == 500
    assert saved.getint("ssh_key_manager", "height") == 400

    # Reload manager to ensure saved size is applied
    geometry_calls.clear()
    manager = ui.SSHKeyManager(None, controller)
    assert "500x400" in geometry_calls
