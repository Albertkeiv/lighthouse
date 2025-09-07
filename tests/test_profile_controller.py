import configparser
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app.controllers.profile_controller import ProfileController
from lighthouse_app.profiles import PROFILES_FILE


def _load_cfg() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profiles_test_config.ini"))
    return cfg


def test_controller_delegates_to_service(monkeypatch):
    cfg = _load_cfg()
    controller = ProfileController()
    called = {}

    def fake_create(name, key_path, ip=None, auto_ip=True, file_path=None):
        called["args"] = (name, key_path, ip, auto_ip, file_path)
        return {"name": name}

    monkeypatch.setattr(controller.service, "create_profile", fake_create)
    key_path = Path(cfg["profile1"]["ssh_key_filename"])
    result = controller.create_profile(cfg["profile1"]["name"], key_path)
    assert result["name"] == cfg["profile1"]["name"]
    assert called["args"][0] == cfg["profile1"]["name"]


def test_load_profiles_delegates_to_service(monkeypatch):
    cfg = _load_cfg()
    controller = ProfileController()
    expected = [{"name": cfg["profile1"]["name"]}]
    called = {}

    def fake_load(file_path=PROFILES_FILE):
        called["file_path"] = file_path
        return expected

    monkeypatch.setattr(controller.service, "load_profiles", fake_load)
    result = controller.load_profiles()
    assert result == expected
    assert called["file_path"] == PROFILES_FILE


def test_start_stop_profile_delegates_to_service(monkeypatch):
    cfg = _load_cfg()
    controller = ProfileController()
    name = cfg["profile1"]["name"]
    called = {}

    def fake_start(profile_name, file_path=PROFILES_FILE, profiles=None, forwarder_cls=None):
        called["start"] = (profile_name, file_path)

    def fake_stop(profile_name):
        called["stop"] = profile_name

    monkeypatch.setattr(controller.service, "start_profile", fake_start)
    monkeypatch.setattr(controller.service, "stop_profile", fake_stop)

    controller.start_profile(name)
    controller.stop_profile(name)

    assert called["start"] == (name, PROFILES_FILE)
    assert called["stop"] == name
