import configparser
from pathlib import Path
import sys
from types import SimpleNamespace

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _load_cfg() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profile_tunnels_test_config.ini"))
    return cfg


class _DummyTreeview:
    """Minimal Treeview stand-in storing items and tag configuration."""

    def __init__(self, *args, **kwargs):
        self._items = {}
        self.tag_configs = {}

    def heading(self, *_, **__):
        pass

    def column(self, *_, **__):
        pass

    def pack(self, *_, **__):
        pass

    def bind(self, *_, **__):
        pass

    def tag_configure(self, tag, **opts):
        self.tag_configs[tag] = opts

    def insert(self, _parent, _index, values=()):
        item_id = f"item{len(self._items)}"
        self._items[item_id] = {"values": values, "tags": ()}
        return item_id

    def get_children(self):
        return list(self._items.keys())

    def item(self, item_id, option=None, **kwargs):
        if kwargs:
            if "tags" in kwargs:
                self._items[item_id]["tags"] = kwargs["tags"]
        if option == "values":
            return self._items[item_id]["values"]
        return self._items[item_id]

    def selection(self):
        return ("item0",)


class _DummyWidget:
    def __init__(self, *args, **kwargs):
        pass

    def grid(self, *args, **kwargs):
        pass

    def pack(self, *args, **kwargs):
        pass

    def bind(self, *args, **kwargs):
        pass

    def rowconfigure(self, *args, **kwargs):
        pass

    def columnconfigure(self, *args, **kwargs):
        pass

    def after(self, delay, callback, *args):
        callback(*args)

    def update_idletasks(self):
        pass


class _DummyPanedWindow(_DummyWidget):
    def add(self, child, **kwargs):
        pass


class _DummyText(_DummyWidget):
    def insert(self, *args, **kwargs):
        pass


class _DummyButton(_DummyWidget):
    def __init__(self, *args, **kwargs):
        pass


def _make_app(monkeypatch, cfg):
    fake_tk = SimpleNamespace(
        PanedWindow=_DummyPanedWindow,
        Frame=_DummyWidget,
        LabelFrame=_DummyWidget,
        Text=_DummyText,
        Button=_DummyButton,
        END="end",
        HORIZONTAL="horizontal",
        BOTH="both",
        GROOVE="groove",
    )
    fake_ttk = SimpleNamespace(Treeview=_DummyTreeview)
    monkeypatch.setattr(ui, "tk", fake_tk)
    monkeypatch.setattr(ui, "ttk", fake_ttk)
    monkeypatch.setattr(ui, "load_pane_layout", lambda file_path=ui.PANE_LAYOUT_FILE: [])
    monkeypatch.setattr(ui.LighthouseApp, "_setup_logging", lambda self: None)
    monkeypatch.setattr(ui.LighthouseApp, "_load_profiles_into_list", lambda self: None)
    root = _DummyWidget()
    app = ui.LighthouseApp(root, cfg)
    return app


def test_active_items_highlight(monkeypatch) -> None:
    cfg = _load_cfg()
    app = _make_app(monkeypatch, cfg)

    profile_name = cfg["profile"]["name"]
    ip = cfg["profile"]["ip"]
    tunnel_name = cfg["tunnel"]["name"]
    target = f"{cfg['tunnel']['remote_host']}:{cfg['tunnel']['remote_port']}"

    app.profile_list.insert("", "end", values=(profile_name, ip))
    app.tunnel_list.insert("", "end", values=(tunnel_name, target))

    expected_color = cfg["colors"]["active"]
    assert app.profile_list.tag_configs["active"]["foreground"] == expected_color
    assert app.tunnel_list.tag_configs["active"]["foreground"] == expected_color

    profiles = [
        {
            "name": profile_name,
            "ssh_key": str(Path(cfg["profile"]["ssh_dir"]) / cfg["profile"]["ssh_key_filename"]),
            "ip": ip,
            "tunnels": [
                {
                    "name": tunnel_name,
                    "local_port": int(cfg["tunnel"]["local_port"]),
                    "remote_host": cfg["tunnel"]["remote_host"],
                    "remote_port": int(cfg["tunnel"]["remote_port"]),
                    "ssh_host": cfg["tunnel"]["ssh_host"],
                    "username": cfg["tunnel"]["username"],
                    "ssh_port": int(cfg["tunnel"]["ssh_port"]),
                }
            ],
        }
    ]
    monkeypatch.setattr(app.profile_controller, "load_profiles", lambda: profiles)
    monkeypatch.setattr(ui.messagebox, "showerror", lambda *a, **k: None)
    monkeypatch.setattr(ui.messagebox, "showwarning", lambda *a, **k: None)

    class DummyForwarder:
        def __init__(self, **_kwargs):
            self.started = False

        def start(self):
            self.started = True

        def stop(self):
            self.started = False

        @property
        def is_active(self):
            return self.started

    import lighthouse_app.services.profile_service as ps
    monkeypatch.setattr(ps, "SSHTunnelForwarder", DummyForwarder)

    app.profile_controller.active_tunnels = {}
    app._on_start_tunnel()
    assert "active" in app.profile_list._items["item0"]["tags"]
    assert "active" in app.tunnel_list._items["item0"]["tags"]

    app._on_stop_tunnel()
    assert app.profile_list._items["item0"]["tags"] == ()
    assert app.tunnel_list._items["item0"]["tags"] == ()
