import configparser
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app.controllers.profile_controller import ProfileController


def _load_cfg() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profiles_test_config.ini"))
    return cfg


def test_controller_delegates_to_service(monkeypatch):
    cfg = _load_cfg()
    controller = ProfileController()
    called = {}

    def fake_create(name, key_path, ip=None, file_path=None):
        called["args"] = (name, key_path, ip, file_path)
        return {"name": name}

    monkeypatch.setattr(controller.service, "create_profile", fake_create)
    key_path = Path(cfg["profile1"]["ssh_key_filename"])
    result = controller.create_profile(cfg["profile1"]["name"], key_path)
    assert result["name"] == cfg["profile1"]["name"]
    assert called["args"][0] == cfg["profile1"]["name"]
