import configparser
from pathlib import Path
from unittest.mock import patch

from lighthouse_app import ui


class DummyTreeview:
    """Minimal stand-in for ttk.Treeview used in highlight tests."""

    def __init__(self):
        self._items = {}

    def insert(self, _parent, _index, values=()):
        item_id = f"item{len(self._items)}"
        self._items[item_id] = {"values": values, "tags": ()}
        return item_id

    def get_children(self):
        return list(self._items.keys())

    def item(self, item_id, option=None, **kwargs):
        if kwargs and "tags" in kwargs:
            self._items[item_id]["tags"] = kwargs["tags"]
        if option == "values":
            return self._items[item_id]["values"]
        return self._items[item_id]

    def selection(self):
        return tuple(self._items.keys())[:1]


def _load_cfg() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("profile_tunnels_test_config.ini"))
    return cfg


def test_update_highlights_without_tunnel_list() -> None:
    cfg = _load_cfg()
    with patch.object(ui.LighthouseApp, "_setup_logging", lambda self: None), \
         patch.object(ui.LighthouseApp, "_build_ui", lambda self: None):
        app = ui.LighthouseApp(object(), cfg)

    # Provide a minimal profile list and deliberately omit ``tunnel_list``.
    app.profile_list = DummyTreeview()
    app.profile_list.insert("", "end", values=(cfg["profile"]["name"], cfg["profile"]["ip"]))

    # Should not raise even though ``tunnel_list`` is absent.
    app._update_highlights()
