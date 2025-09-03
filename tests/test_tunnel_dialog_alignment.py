import configparser
from pathlib import Path
import logging
from types import SimpleNamespace
import sys

# Ensure application importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_tunnel_dialog_alignment(monkeypatch) -> None:
    """Labels share width, entries expand and dialog widens as configured."""
    cfg = configparser.ConfigParser()
    cfg.read(Path(__file__).with_name("tunnel_dialog_config.ini"))

    label_texts = list(cfg["labels"].values())
    expected_width = max(len(t) for t in label_texts)
    base_width = cfg.getint("dialog", "base_width")
    extra_width = cfg.getint("dialog", "extra_width")

    label_widths = []
    entry_stickies = []
    geometry_called = {}
    column_configs = {}

    class DummyEntry:
        def __init__(self, *_, **__):
            self.grid_kwargs = {}
        def grid(self, *_, **kwargs):
            self.grid_kwargs = kwargs
            entry_stickies.append(kwargs.get("sticky"))
        def insert(self, *_):
            pass
        def get(self):
            return ""
        def configure(self, *_, **__):
            pass

    class DummyLabel:
        def __init__(self, master=None, text="", width=None, anchor=None):
            label_widths.append(width)
        def grid(self, *_, **__):
            pass
        def configure(self, *_, **__):
            pass

    class DummyFrame:
        def grid(self, *_, **__):
            pass
        def columnconfigure(self, col, weight):
            column_configs.setdefault(self, []).append((col, weight))

    class DummyLabelFrame(DummyFrame):
        def __init__(self, *_, **__):
            super().__init__()

    class DummyListbox:
        def __init__(self, *_, **__):
            pass
        def grid(self, *_, **__):
            pass
        def insert(self, *_):
            pass
        def get(self, start, end):
            return []
        def delete(self, start, end=None):
            pass
        def configure(self, *_, **__):
            pass

    class DummyCheckbutton:
        def __init__(self, *_, **__):
            pass
        def grid(self, *_, **__):
            pass
        def configure(self, *_, **__):
            pass

    class DummyButton:
        def __init__(self, *_, **__):
            pass
        def grid(self, *_, **__):
            pass
        def configure(self, *_, **__):
            pass

    class DummyVar:
        def __init__(self, value=True):
            self.value = value
        def get(self):
            return self.value
        def set(self, value):
            self.value = value

    fake_paramiko = SimpleNamespace(
        RSAKey=object,
        ECDSAKey=object,
        Ed25519Key=object,
        SSHException=Exception,
        PasswordRequiredException=Exception,
    )
    monkeypatch.setitem(sys.modules, "paramiko", fake_paramiko)

    class DummyForwarder:
        pass

    fake_sshtunnel = SimpleNamespace(
        SSHTunnelForwarder=DummyForwarder, DEFAULT_SSH_DIRECTORY="~/.ssh"
    )
    monkeypatch.setitem(sys.modules, "sshtunnel", fake_sshtunnel)

    from lighthouse_app import ui

    fake_tk = SimpleNamespace(
        Label=DummyLabel,
        Entry=DummyEntry,
        Button=DummyButton,
        Frame=DummyFrame,
        LabelFrame=DummyLabelFrame,
        Listbox=DummyListbox,
        Checkbutton=DummyCheckbutton,
        BooleanVar=DummyVar,
        NORMAL="normal",
        DISABLED="disabled",
        END="end",
    )
    monkeypatch.setattr(ui, "tk", fake_tk)

    class DummyDialog(ui.TunnelDialog):
        def __init__(self):
            self.existing_tunnels = []
            self.tunnel = None
            self.dns_names = []
            self.logger = logging.getLogger(__name__)
            self.geom = None
        def update_idletasks(self):
            pass
        def winfo_width(self):
            return base_width
        def winfo_height(self):
            return 200
        def geometry(self, value):
            self.geom = value
        def resizable(self, width, height):
            geometry_called["resizable"] = (width, height)

    master = DummyFrame()
    dialog = DummyDialog()
    dialog.body(master)

    assert all(w == expected_width for w in label_widths if w is not None)
    assert all(sticky == "ew" for sticky in entry_stickies)

    # Ensure both column 0 and 1 are configured to expand
    weights = [cfgs for cfgs in column_configs.values()]
    assert any((0, 1) in w for w in weights)
    assert any((1, 1) in w for w in weights)

    assert dialog.geom == f"{base_width + extra_width}x200"
    assert geometry_called.get("resizable") == (True, True)
