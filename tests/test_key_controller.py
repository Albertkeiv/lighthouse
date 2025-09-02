import configparser
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app.controllers.key_controller import KeyController


def _load_cfg() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("ssh_keys_test_config.ini"))
    return cfg


def test_controller_delegates_to_service(monkeypatch):
    cfg = _load_cfg()
    controller = KeyController()
    called = {}

    def fake_create(name, path, desc, file_path=None):
        called["args"] = (name, path, desc, file_path)
        return {"name": name}

    monkeypatch.setattr(controller.service, "create_key", fake_create)
    key_path = Path(cfg["key1"]["filename"])
    result = controller.create_key(
        cfg["key1"]["name"], key_path, cfg["key1"]["description"]
    )
    assert result["name"] == cfg["key1"]["name"]
    assert called["args"][0] == cfg["key1"]["name"]
