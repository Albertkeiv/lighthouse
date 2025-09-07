import configparser
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app.controllers.profile_controller import ProfileController


def _load_cfg() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profile_tunnels_test_config.ini"))
    return cfg


def test_start_stop_profile(monkeypatch, tmp_path) -> None:
    cfg = _load_cfg()
    profile_name = cfg["profile"]["name"]
    tunnel_cfg = cfg["tunnel"]
    hosts_file = tmp_path / cfg["hosts"]["file"]
    hosts_file.write_text("")
    ssh_key = Path(cfg["profile"]["ssh_dir"]) / cfg["profile"]["ssh_key_filename"]
    profile_ip = cfg["profile"]["ip"]
    profiles = [
        {
            "name": profile_name,
            "ssh_key": str(ssh_key),
            "ip": profile_ip,
            "tunnels": [
                {
                    "name": tunnel_cfg["name"],
                    "local_port": int(tunnel_cfg["local_port"]),
                    "remote_host": tunnel_cfg["remote_host"],
                    "remote_port": int(tunnel_cfg["remote_port"]),
                    "ssh_host": tunnel_cfg["ssh_host"],
                    "username": tunnel_cfg["username"],
                    "ssh_port": int(tunnel_cfg["ssh_port"]),
                    "dns_names": [
                        d.strip()
                        for d in tunnel_cfg["dns_names"].split(",")
                        if d.strip()
                    ],
                    "dns_override": tunnel_cfg.getboolean("dns_override"),
                }
            ],
        }
    ]

    controller = ProfileController(hosts_file=hosts_file)

    class DummyForwarder:
        def __init__(self, **kwargs):
            self.active = False

        def start(self):
            self.active = True

        def stop(self):
            self.active = False

        @property
        def is_active(self):
            return self.active

    controller.start_profile(
        profile_name,
        profiles=profiles,
        forwarder_cls=DummyForwarder,
    )

    assert (profile_name, tunnel_cfg["name"]) in controller.active_tunnels
    dns_line = " ".join(
        [
            profile_ip,
            *[
                d.strip()
                for d in tunnel_cfg["dns_names"].split(",")
                if d.strip()
            ],
        ]
    )
    expected_block = (
        f"#### Managed by Lighthouse profile {profile_name} ####\n"
        f"{dns_line}\n"
        f"#### End block Lighthouse profile {profile_name} ####\n"
    )
    assert hosts_file.read_text() == expected_block

    controller.stop_profile(profile_name)
    assert controller.active_tunnels == {}
    assert hosts_file.read_text() == ""
