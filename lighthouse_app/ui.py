import configparser
import logging
import os
from pathlib import Path
from typing import Dict, List, Union, Optional
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from ipaddress import ip_address

import paramiko
from sshtunnel import SSHTunnelForwarder, DEFAULT_SSH_DIRECTORY


class SafeSSHTunnelForwarder(SSHTunnelForwarder):
    """SSHTunnelForwarder with compatibility for Paramiko without DSSKey."""

    @staticmethod
    def get_keys(
        logger=None, host_pkey_directories=None, allow_agent=False
    ):
        """Load available private keys without assuming DSA support.

        Paramiko 4 removed the ``DSSKey`` class used for DSA keys.  The
        upstream ``sshtunnel`` implementation unconditionally referenced
        ``paramiko.DSSKey`` which now raises :class:`AttributeError`.  This
        reimplementation checks for that attribute before including the DSA
        handler, preventing the application from crashing on startup.

        Parameters mirror the original method.
        """

        keys = (
            SSHTunnelForwarder.get_agent_keys(logger=logger) if allow_agent else []
        )

        if host_pkey_directories is None:
            host_pkey_directories = [DEFAULT_SSH_DIRECTORY]

        paramiko_key_types = {
            "rsa": paramiko.RSAKey,
            "ecdsa": paramiko.ECDSAKey,
        }
        if hasattr(paramiko, "DSSKey"):
            paramiko_key_types["dsa"] = paramiko.DSSKey
        if hasattr(paramiko, "Ed25519Key"):
            paramiko_key_types["ed25519"] = paramiko.Ed25519Key

        for directory in host_pkey_directories:
            for keytype, key_cls in paramiko_key_types.items():
                ssh_pkey_expanded = os.path.expanduser(
                    os.path.join(directory, f"id_{keytype}")
                )
                try:
                    if os.path.isfile(ssh_pkey_expanded):
                        ssh_pkey = SSHTunnelForwarder.read_private_key_file(
                            pkey_file=ssh_pkey_expanded,
                            logger=logger,
                            key_type=key_cls,
                        )
                        if ssh_pkey:
                            keys.append(ssh_pkey)
                except OSError as exc:  # pragma: no cover - defensive
                    if logger:
                        logger.warning(
                            "Private key file %s check error: %s",
                            ssh_pkey_expanded,
                            exc,
                        )
        if logger:
            logger.info("%d key(s) loaded", len(keys))
        return keys


# Replace original forwarder with the safe version for module-wide use
SSHTunnelForwarder = SafeSSHTunnelForwarder

from .profiles import (
    create_profile,
    load_profiles,
    delete_profile,
    update_profile,
    add_tunnel,
    update_tunnel,
    delete_tunnel,
)
from .ssh_keys import (
    create_key as create_ssh_key,
    load_keys as load_ssh_keys,
    delete_key as delete_ssh_key,
    update_key as update_ssh_key,
)

PANE_LAYOUT_FILE = "pane_layout.ini"


def geometry_from_config(cfg: configparser.ConfigParser) -> str:
    """Return geometry string (e.g., '800x600') based on configuration values.

    Parameters
    ----------
    cfg: configparser.ConfigParser
        Parsed configuration object containing 'ui' section with 'width' and 'height'.
    """
    width = cfg.getint('ui', 'width', fallback=800)
    height = cfg.getint('ui', 'height', fallback=600)
    return f"{width}x{height}"


def sash_width_from_config(cfg: configparser.ConfigParser) -> int:
    """Return sash width for resizable panes.

    Ensures a positive integer is always returned, falling back to ``1``.
    """
    width = cfg.getint('ui', 'sash_width', fallback=1)
    if width < 1:
        width = 1
    return width


def load_pane_layout(file_path: Union[str, Path] = PANE_LAYOUT_FILE) -> List[int]:
    """Load saved sash x-coordinates from a configuration file.

    Parameters
    ----------
    file_path: str | Path
        Path to the user-specific pane layout file.

    Returns
    -------
    List[int]
        List of x-coordinates for each sash. Empty if unavailable.
    """
    logger = logging.getLogger(__name__)
    cfg = configparser.ConfigParser()
    path = Path(file_path)
    if not path.exists():
        logger.info("Pane layout file %s not found", path)
        return []
    try:
        cfg.read(path)
        if not cfg.has_section("panes"):
            logger.info("Pane layout file missing 'panes' section")
            return []
        coords = []
        for key in sorted(cfg["panes"], key=lambda k: int(k.split("_")[-1])):
            coords.append(cfg.getint("panes", key, fallback=0))
        logger.info("Loaded pane layout: %s", coords)
        return coords
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Failed to load pane layout: %s", exc)
        return []


def save_pane_layout(coords: List[int], file_path: Union[str, Path] = PANE_LAYOUT_FILE) -> None:
    """Persist sash x-coordinates to a configuration file."""
    logger = logging.getLogger(__name__)
    cfg = configparser.ConfigParser()
    cfg["panes"] = {f"sash_{i}": str(x) for i, x in enumerate(coords)}
    try:
        with open(file_path, "w", encoding="utf-8") as handle:
            cfg.write(handle)
        logger.info("Saved pane layout: %s", coords)
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Failed to save pane layout: %s", exc)


class ProfileDialog(simpledialog.Dialog):
    """Dialog window for collecting or editing profile parameters."""

    def __init__(
        self,
        parent: tk.Tk,
        existing_profiles: List[dict],
        profile: Optional[dict] = None,
    ):
        self.existing_profiles = existing_profiles
        self.profile = profile
        self.logger = logging.getLogger(__name__)
        title = "Edit Profile" if profile is not None else "Create Profile"
        super().__init__(parent, title)

    @staticmethod
    def _load_key_map() -> Dict[str, str]:
        """Return mapping of SSH key names to their paths."""
        logger = logging.getLogger(__name__)
        try:
            keys = load_ssh_keys()
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Failed to load SSH keys: %s", exc)
            return {}
        mapping = {
            k.get("name", ""): k.get("path", "")
            for k in keys
            if k.get("name") and k.get("path")
        }
        logger.info("Loaded %d SSH keys for profile dialog", len(mapping))
        return mapping

    def body(self, master: tk.Misc) -> tk.Entry:
        tk.Label(master, text="Profile name:").grid(row=0, column=0, sticky="w")
        self.name_entry = tk.Entry(master)
        self.name_entry.grid(row=0, column=1)

        tk.Label(master, text="SSH key:").grid(row=1, column=0, sticky="w")
        # Prepare drop-down of available SSH keys
        self.key_var = tk.StringVar()
        self.key_combo = ttk.Combobox(
            master, textvariable=self.key_var, state="readonly"
        )
        # Map of key names to file system paths
        self.key_map = self._load_key_map()
        self.key_combo["values"] = list(self.key_map.keys())
        self.key_combo.grid(row=1, column=1)

        auto_default = True if self.profile is None else False
        self.auto_var = tk.BooleanVar(value=auto_default)
        auto_chk = tk.Checkbutton(
            master,
            text="Assign IP automatically",
            variable=self.auto_var,
            command=self._toggle_ip_entry,
        )
        auto_chk.grid(row=2, column=0, columnspan=2, sticky="w")

        tk.Label(master, text="IP address:").grid(row=3, column=0, sticky="w")
        self.ip_entry = tk.Entry(master)
        self.ip_entry.grid(row=3, column=1)
        self.ip_entry.configure(state="disabled" if auto_default else "normal")

        if self.profile is not None:
            self.name_entry.insert(0, self.profile.get("name", ""))
            # Pre-select SSH key based on stored path
            existing_path = self.profile.get("ssh_key", "")
            for key_name, key_path in self.key_map.items():
                if key_path == existing_path:
                    self.key_var.set(key_name)
                    break
            self.ip_entry.insert(0, self.profile.get("ip", ""))

        return self.name_entry

    def _toggle_ip_entry(self) -> None:
        if self.auto_var.get():
            self.ip_entry.configure(state="disabled")
            self.logger.info("Profile dialog: automatic IP selected")
        else:
            self.ip_entry.configure(state="normal")
            self.logger.info("Profile dialog: manual IP selected")

    def validate(self) -> bool:  # pragma: no cover - GUI validation
        name = self.name_entry.get().strip()
        key_name = self.key_var.get().strip()
        ip_str = self.ip_entry.get().strip()

        if not name:
            messagebox.showerror("Error", "Profile name must be provided")
            return False
        existing_name = (self.profile or {}).get("name")
        if any(
            p.get("name") == name and p.get("name") != existing_name
            for p in self.existing_profiles
        ):
            messagebox.showerror("Error", f"Profile '{name}' already exists")
            self.logger.warning("Profile creation aborted: name '%s' exists", name)
            return False
        if not key_name or key_name not in self.key_map:
            messagebox.showerror("Error", "SSH key must be selected")
            return False
        if not self.auto_var.get():
            if not ip_str:
                messagebox.showerror(
                    "Error", "IP address required or enable automatic assignment"
                )
                return False
            try:
                ip_address(ip_str)
            except ValueError:
                messagebox.showerror("Error", f"Invalid IP address: {ip_str}")
                return False
            if any(
                p.get("ip") == ip_str and p.get("name") != existing_name
                for p in self.existing_profiles
            ):
                messagebox.showerror("Error", f"IP address {ip_str} is already in use")
                return False
        return True

    def apply(self) -> None:  # pragma: no cover - GUI side effect
        name = self.name_entry.get().strip()
        key_name = self.key_var.get().strip()
        key_path = self.key_map.get(key_name, "")
        ip_str = None if self.auto_var.get() else self.ip_entry.get().strip()
        self.result = (name, key_path, ip_str)
        self.logger.info(
            "Profile dialog confirmed for '%s' with key '%s'", name, key_name
        )

    def cancel(self, event=None) -> None:  # pragma: no cover - GUI side effect
        self.logger.info("Profile dialog cancelled")
        super().cancel(event)


class SSHKeyDialog(simpledialog.Dialog):
    """Dialog window for collecting or editing SSH key parameters."""

    def __init__(
        self,
        parent: tk.Tk,
        existing_keys: List[dict],
        key: Optional[dict] = None,
    ):
        self.existing_keys = existing_keys
        self.key = key
        self.logger = logging.getLogger(__name__)
        title = "Edit SSH Key" if key is not None else "Add SSH Key"
        super().__init__(parent, title)

    def body(self, master: tk.Misc) -> tk.Entry:
        tk.Label(master, text="Key name:").grid(row=0, column=0, sticky="w")
        self.name_entry = tk.Entry(master)
        self.name_entry.grid(row=0, column=1)

        tk.Label(master, text="Key path:").grid(row=1, column=0, sticky="w")
        self.path_entry = tk.Entry(master)
        self.path_entry.grid(row=1, column=1)

        tk.Label(master, text="Description:").grid(row=2, column=0, sticky="w")
        self.desc_entry = tk.Entry(master)
        self.desc_entry.grid(row=2, column=1)

        if self.key is not None:
            self.name_entry.insert(0, self.key.get("name", ""))
            self.path_entry.insert(0, self.key.get("path", ""))
            self.desc_entry.insert(0, self.key.get("description", ""))

        return self.name_entry

    def validate(self) -> bool:  # pragma: no cover - GUI validation
        name = self.name_entry.get().strip()
        path = self.path_entry.get().strip()

        if not name:
            messagebox.showerror("Error", "Key name must be provided")
            return False
        existing_name = (self.key or {}).get("name")
        if any(
            k.get("name") == name and k.get("name") != existing_name
            for k in self.existing_keys
        ):
            messagebox.showerror("Error", f"SSH key '{name}' already exists")
            self.logger.warning("SSH key dialog aborted: name '%s' exists", name)
            return False
        if not path:
            messagebox.showerror("Error", "Key path must be provided")
            return False
        if not Path(path).expanduser().exists():
            messagebox.showerror("Error", f"SSH key not found: {path}")
            return False
        return True

    def apply(self) -> None:  # pragma: no cover - GUI side effect
        name = self.name_entry.get().strip()
        path = self.path_entry.get().strip()
        desc = self.desc_entry.get().strip()
        self.result = (name, path, desc)
        self.logger.info("SSH key dialog confirmed for '%s'", name)

    def cancel(self, event=None) -> None:  # pragma: no cover - GUI side effect
        self.logger.info("SSH key dialog cancelled")
        super().cancel(event)


class TunnelDialog(simpledialog.Dialog):
    """Dialog window for collecting or editing tunnel parameters."""

    def __init__(
        self,
        parent: tk.Tk,
        existing_tunnels: List[dict],
        tunnel: Optional[dict] = None,
    ):
        self.existing_tunnels = existing_tunnels
        self.tunnel = tunnel
        # Store DNS names entered by user; populated during validation
        self.dns_names: List[str] = []
        self.logger = logging.getLogger(__name__)
        title = "Edit Tunnel" if tunnel is not None else "New Tunnel"
        super().__init__(parent, title)

    def body(self, master: tk.Misc) -> tk.Entry:
        tk.Label(master, text="Tunnel name:").grid(row=0, column=0, sticky="w")
        self.name_entry = tk.Entry(master)
        self.name_entry.grid(row=0, column=1)

        tk.Label(master, text="Local port:").grid(row=1, column=0, sticky="w")
        self.local_entry = tk.Entry(master)
        self.local_entry.grid(row=1, column=1)
        tk.Label(master, text="SSH host:").grid(row=2, column=0, sticky="w")
        self.ssh_host_entry = tk.Entry(master)
        self.ssh_host_entry.grid(row=2, column=1)

        tk.Label(master, text="Username:").grid(row=3, column=0, sticky="w")
        self.user_entry = tk.Entry(master)
        self.user_entry.grid(row=3, column=1)

        tk.Label(master, text="SSH port:").grid(row=4, column=0, sticky="w")
        self.ssh_port_entry = tk.Entry(master)
        self.ssh_port_entry.grid(row=4, column=1)

        tk.Label(master, text="Remote host:").grid(row=5, column=0, sticky="w")
        self.host_entry = tk.Entry(master)
        self.host_entry.grid(row=5, column=1)

        tk.Label(master, text="Remote port:").grid(row=6, column=0, sticky="w")
        self.remote_entry = tk.Entry(master)
        self.remote_entry.grid(row=6, column=1)

        tk.Label(master, text="DNS names:").grid(row=7, column=0, sticky="nw")
        dns_frame = tk.Frame(master)
        dns_frame.grid(row=7, column=1, sticky="w")
        self.dns_list = tk.Listbox(dns_frame, height=3)
        self.dns_list.grid(row=0, column=0, rowspan=3, sticky="nsew")
        self.dns_entry = tk.Entry(dns_frame)
        self.dns_entry.grid(row=0, column=1, sticky="ew")
        add_btn = tk.Button(dns_frame, text="Add", command=self._add_dns)
        add_btn.grid(row=1, column=1, sticky="ew")
        del_btn = tk.Button(dns_frame, text="Remove", command=self._remove_dns)
        del_btn.grid(row=2, column=1, sticky="ew")
        dns_frame.columnconfigure(0, weight=1)

        if self.tunnel is not None:
            self.name_entry.insert(0, self.tunnel.get("name", ""))
            self.local_entry.insert(0, str(self.tunnel.get("local_port", "")))
            self.ssh_host_entry.insert(0, self.tunnel.get("ssh_host", ""))
            self.user_entry.insert(0, self.tunnel.get("username", ""))
            self.ssh_port_entry.insert(0, str(self.tunnel.get("ssh_port", "")))
            self.host_entry.insert(0, self.tunnel.get("remote_host", ""))
            self.remote_entry.insert(0, str(self.tunnel.get("remote_port", "")))
            existing_dns = self.tunnel.get("dns_names") or []
            if not existing_dns and self.tunnel.get("dns_name"):
                existing_dns = [self.tunnel.get("dns_name")]
            for dns in existing_dns:
                self.dns_list.insert(tk.END, dns)
        else:
            # Fill SSH port with safe default for new tunnels
            self.ssh_port_entry.insert(0, "22")
            self.logger.info("Tunnel dialog: default SSH port 22 inserted")

        return self.name_entry

    def validate(self) -> bool:  # pragma: no cover - GUI validation
        name = self.name_entry.get().strip()
        local = self.local_entry.get().strip()
        ssh_host = self.ssh_host_entry.get().strip()
        username = self.user_entry.get().strip()
        ssh_port = self.ssh_port_entry.get().strip()
        host = self.host_entry.get().strip()
        remote = self.remote_entry.get().strip()
        # Collect DNS names; the list can be empty
        self.dns_names = list(self.dns_list.get(0, tk.END))

        if not all([name, local, ssh_host, username, ssh_port, host, remote]):
            messagebox.showerror("Error", "All fields must be provided")
            return False

        existing_name = (self.tunnel or {}).get("name")
        if any(
            t.get("name") == name and t.get("name") != existing_name
            for t in self.existing_tunnels
        ):
            messagebox.showerror("Error", f"Tunnel '{name}' already exists")
            self.logger.warning("Tunnel dialog aborted: name '%s' exists", name)
            return False

        for label, value in {
            "Local port": local,
            "SSH port": ssh_port,
            "Remote port": remote,
        }.items():
            try:
                port = int(value)
            except ValueError:
                messagebox.showerror("Error", f"{label} must be an integer")
                return False
            if not (1 <= port <= 65535):
                messagebox.showerror(
                    "Error", f"{label} must be between 1 and 65535",
                )
                return False

        return True

    def apply(self) -> None:  # pragma: no cover - GUI side effect
        name = self.name_entry.get().strip()
        local = int(self.local_entry.get().strip())
        ssh_host = self.ssh_host_entry.get().strip()
        username = self.user_entry.get().strip()
        ssh_port = int(self.ssh_port_entry.get().strip())
        host = self.host_entry.get().strip()
        remote = int(self.remote_entry.get().strip())
        dns_list = self.dns_names
        self.result = (
            name,
            ssh_host,
            username,
            local,
            host,
            remote,
            ssh_port,
            dns_list,
        )
        self.logger.info(
            "Tunnel dialog confirmed for '%s' with DNS '%s'",
            name,
            ", ".join(dns_list),
        )

    def cancel(self, event=None) -> None:  # pragma: no cover - GUI side effect
        self.logger.info("Tunnel dialog cancelled")
        super().cancel(event)

    def _add_dns(self) -> None:  # pragma: no cover - GUI helper
        """Add DNS name from entry to listbox."""
        name = self.dns_entry.get().strip()
        if not name:
            return
        existing = self.dns_list.get(0, tk.END)
        if name not in existing:
            self.dns_list.insert(tk.END, name)
            self.logger.info("DNS name added: %s", name)
        self.dns_entry.delete(0, tk.END)

    def _remove_dns(self) -> None:  # pragma: no cover - GUI helper
        """Remove selected DNS name from listbox."""
        selection = self.dns_list.curselection()
        if not selection:
            return
        idx = selection[0]
        name = self.dns_list.get(idx)
        self.dns_list.delete(idx)
        self.logger.info("DNS name removed: %s", name)


class SSHKeyManager:
    """Window for managing SSH keys."""

    def __init__(self, parent: tk.Tk) -> None:
        self.parent = parent
        self.logger = logging.getLogger(__name__)
        self.top = tk.Toplevel(parent)
        self.top.title("SSH Keys")
        # Make the management window wider for better readability of
        # key names and their descriptions.
        self.top.geometry("600x400")

        self.key_table = ttk.Treeview(
            self.top,
            columns=("name", "description"),
            show="headings",
        )
        self.key_table.heading("name", text="Name")
        self.key_table.heading("description", text="Description")
        self.key_table.pack(fill=tk.BOTH, expand=True)
        self.key_table.bind("<Double-1>", self._on_double_click)

        add_btn = tk.Button(self.top, text="Add SSH key", command=self._on_add)
        add_btn.pack(fill="x")
        edit_btn = tk.Button(self.top, text="Edit SSH key", command=self._on_edit)
        edit_btn.pack(fill="x")
        del_btn = tk.Button(self.top, text="Delete SSH key", command=self._on_delete)
        del_btn.pack(fill="x")

        self._load_keys()

    def _load_keys(self) -> None:
        try:
            keys = load_ssh_keys()
            for key in keys:
                self.key_table.insert(
                    "",
                    tk.END,
                    values=(key["name"], key.get("description", "")),
                )
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to load SSH keys: %s", exc)

    def _on_add(self) -> None:
        self.logger.info("SSH key addition requested")
        try:
            keys = load_ssh_keys()
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to load SSH keys for dialog: %s", exc)
            messagebox.showerror("Error", "Failed to load SSH keys")
            return
        dialog = SSHKeyDialog(self.top, keys)
        if not getattr(dialog, "result", None):
            self.logger.info("SSH key addition cancelled by user")
            return
        name, path, desc = dialog.result
        try:
            key = create_ssh_key(name, path, desc)
            self.key_table.insert(
                "",
                tk.END,
                values=(key["name"], key.get("description", "")),
            )
            self.logger.info("SSH key '%s' added", key["name"])
        except Exception as exc:
            self.logger.exception("Failed to add SSH key: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_edit(self) -> None:
        self.logger.info("SSH key edit requested")
        selection = self.key_table.selection()
        if not selection:
            messagebox.showwarning(
                "No selection", "Please select an SSH key to edit."
            )
            self.logger.info("SSH key edit cancelled: no key selected")
            return
        item_id = selection[0]
        item = self.key_table.item(item_id)
        name = item["values"][0]
        try:
            keys = load_ssh_keys()
            key = next((k for k in keys if k.get("name") == name), None)
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to load SSH keys for edit: %s", exc)
            messagebox.showerror("Error", "Failed to load SSH keys")
            return
        if key is None:
            messagebox.showerror("Error", f"SSH key '{name}' not found")
            self.logger.warning("SSH key '%s' not found during edit", name)
            return
        dialog = SSHKeyDialog(self.top, keys, key)
        if not getattr(dialog, "result", None):
            self.logger.info("SSH key edit cancelled by user")
            return
        new_name, path, desc = dialog.result
        try:
            updated = update_ssh_key(name, new_name, path, desc)
            self.key_table.item(
                item_id,
                values=(updated["name"], updated.get("description", "")),
            )
            self.logger.info("SSH key '%s' updated", updated["name"])
        except Exception as exc:
            self.logger.exception("Failed to update SSH key: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_double_click(self, event) -> None:  # pragma: no cover - GUI event
        self.logger.info("SSH key double-click event")
        self._on_edit()

    def _on_delete(self) -> None:
        self.logger.info("SSH key deletion requested")
        selection = self.key_table.selection()
        if not selection:
            messagebox.showwarning(
                "No selection", "Please select an SSH key to delete."
            )
            self.logger.info("SSH key deletion cancelled: no key selected")
            return
        item_id = selection[0]
        item = self.key_table.item(item_id)
        name = item["values"][0]
        if not messagebox.askyesno("Confirm", f"Delete SSH key '{name}'?"):
            self.logger.info("SSH key deletion cancelled by user")
            return
        try:
            removed = delete_ssh_key(name)
            if removed:
                self.key_table.delete(item_id)
                messagebox.showinfo("Deleted", f"SSH key '{name}' deleted")
                self.logger.info("SSH key '%s' deleted", name)
            else:
                messagebox.showwarning("Not found", f"SSH key '{name}' not found")
                self.logger.warning(
                    "SSH key '%s' not found during deletion", name
                )
        except Exception as exc:
            self.logger.exception("Failed to delete SSH key: %s", exc)
            messagebox.showerror("Error", str(exc))

class LighthouseApp:
    """Graphical interface for managing profiles and tunnels.

    This class constructs the Tkinter widgets according to the desired layout
    and logs all user actions for easier debugging.
    """

    def __init__(self, root: tk.Tk, cfg: configparser.ConfigParser) -> None:
        self.root = root
        self.cfg = cfg
        self.logger = logging.getLogger(__name__)
        # Track active SSH tunnels; keys are (profile_name, tunnel_name)
        self.active_tunnels: Dict[tuple, SSHTunnelForwarder] = {}
        self._setup_logging()
        self._build_ui()

    def _setup_logging(self) -> None:
        """Configure logging to file and console."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("app.log"),
                logging.StreamHandler()
            ]
        )

    def _build_ui(self) -> None:
        """Create and arrange widgets using a resizable paned window."""
        # Configure grid for the main window. Only one row and column are
        # required because all control buttons now live inside their
        # respective panes instead of in a separate bottom row.
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Paned window to allow user resizing between sections
        sash_width = sash_width_from_config(self.cfg)
        self.top_pane = tk.PanedWindow(
            self.root, orient=tk.HORIZONTAL, sashwidth=sash_width
        )
        self.top_pane.grid(row=0, column=0, sticky="nsew")
        self.top_pane.bind("<ButtonRelease-1>", self._on_pane_resize)

        # Profiles list displayed as a table for clarity
        profile_frame = tk.Frame(self.top_pane, bd=2, relief=tk.GROOVE)
        self.top_pane.add(profile_frame, minsize=100)
        self.profile_list = ttk.Treeview(
            profile_frame,
            columns=("name", "ip"),
            show="headings",
        )
        # Human friendly column headings
        self.profile_list.heading("name", text="Name")
        self.profile_list.heading("ip", text="Local IP Address")
        # Ensure columns resize with the containing widget
        self.profile_list.column("name", anchor="w", stretch=True)
        self.profile_list.column("ip", anchor="w", stretch=True)
        self.profile_list.pack(fill=tk.BOTH, expand=True)
        self.profile_list.bind("<<TreeviewSelect>>", self._on_profile_select)
        self.profile_list.bind("<Double-1>", self._on_profile_double_click)
        # Adjust column widths whenever the widget size changes
        self.profile_list.bind("<Configure>", self._on_profile_list_configure)
        new_profile_btn = tk.Button(
            profile_frame, text="New Profile", command=self._on_new_profile
        )
        new_profile_btn.pack(fill="x")
        edit_btn = tk.Button(
            profile_frame, text="Edit Profile", command=self._on_edit_profile
        )
        edit_btn.pack(fill="x")
        delete_btn = tk.Button(
            profile_frame, text="Delete Profile", command=self._on_delete_profile
        )
        delete_btn.pack(fill="x")
        self._load_profiles_into_list()

        # Tunnels list
        tunnel_frame = tk.Frame(self.top_pane, bd=2, relief=tk.GROOVE)
        self.top_pane.add(tunnel_frame, minsize=100)
        # Display tunnels in a table with tunnel name and target host
        self.tunnel_list = ttk.Treeview(
            tunnel_frame,
            columns=("name", "target"),
            show="headings",
        )
        self.tunnel_list.heading("name", text="Tunnel name")
        self.tunnel_list.heading("target", text="Target")
        self.tunnel_list.column("name", anchor="w", stretch=True)
        self.tunnel_list.column("target", anchor="w", stretch=True)
        self.tunnel_list.pack(fill=tk.BOTH, expand=True)
        self.tunnel_list.bind("<<TreeviewSelect>>", self._on_tunnel_select)
        self.tunnel_list.bind("<Double-1>", self._on_tunnel_double_click)
        # Adjust column widths whenever the widget size changes
        self.tunnel_list.bind("<Configure>", self._on_tunnel_list_configure)
        new_tunnel_btn = tk.Button(
            tunnel_frame, text="New Tunnel", command=self._on_new_tunnel
        )
        new_tunnel_btn.pack(fill="x")
        edit_tunnel_btn = tk.Button(
            tunnel_frame, text="Edit Tunnel", command=self._on_edit_tunnel
        )
        edit_tunnel_btn.pack(fill="x")
        delete_tunnel_btn = tk.Button(
            tunnel_frame, text="Delete Tunnel", command=self._on_delete_tunnel
        )
        delete_tunnel_btn.pack(fill="x")
        start_tunnel_btn = tk.Button(
            tunnel_frame, text="Start Tunnel", command=self._on_start_tunnel
        )
        start_tunnel_btn.pack(fill="x")
        stop_tunnel_btn = tk.Button(
            tunnel_frame, text="Stop Tunnel", command=self._on_stop_tunnel
        )
        stop_tunnel_btn.pack(fill="x")

        # Info and log area
        info_frame = tk.Frame(self.top_pane)
        self.top_pane.add(info_frame, minsize=200)
        info_frame.rowconfigure(0, weight=3)
        info_frame.rowconfigure(1, weight=1)
        info_frame.rowconfigure(2, weight=0)
        # Ensure the info and log section stretches horizontally with window
        info_frame.columnconfigure(0, weight=1)

        # Restore pane layout after all panes have been added.
        # Calling this earlier results in errors because sashes do not yet exist.
        self.root.after(0, self._restore_pane_layout)

        self.status_text = tk.Text(info_frame, height=10)
        self.status_text.grid(row=0, column=0, sticky="nsew")
        self.status_text.insert(tk.END, "<TUNNEL_INFO_AND_STATUS>")

        self.log_text = tk.Text(info_frame, height=8)
        self.log_text.grid(row=1, column=0, sticky="nsew")
        self.log_text.insert(tk.END, "<LOG>")
        # Frame to hold bottom action buttons side by side
        button_frame = tk.Frame(info_frame)
        button_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
        button_frame.columnconfigure(0, weight=1)
        button_frame.columnconfigure(1, weight=1)

        # Button for managing SSH keys
        self.manage_ssh_btn = tk.Button(
            button_frame, text="Manage SSH Key", command=self._on_manage_ssh_key
        )
        self.manage_ssh_btn.grid(row=0, column=0, sticky="ew", padx=(0, 5))

        # General settings button
        self.settings_btn = tk.Button(
            button_frame, text="Settings", command=self._on_settings
        )
        self.settings_btn.grid(row=0, column=1, sticky="ew")

    def _restore_pane_layout(self) -> None:
        """Apply saved pane positions if available."""
        coords = load_pane_layout()
        # Ensure geometry calculations are current before placing sashes.
        self.root.update_idletasks()
        for idx, x in enumerate(coords):
            try:
                self.top_pane.sash_place(idx, x, 0)
            except Exception as exc:
                self.logger.warning(
                    "Failed to restore sash %s position: %s", idx, exc
                )

    def _on_profile_select(self, event: tk.Event) -> None:
        """Handle profile selection event."""
        selected = event.widget.selection()
        if selected:
            values = event.widget.item(selected[0], "values")
            profile_name = values[0]
            if len(values) >= 2:
                self.logger.info(
                    "Profile selected: %s (%s)", profile_name, values[1]
                )
            else:  # pragma: no cover - defensive
                self.logger.info("Profile selected: %s", profile_name)
            self._load_tunnels(profile_name)

    def _on_profile_double_click(self, event: tk.Event) -> None:  # pragma: no cover - GUI event
        """Open the profile edit dialog when a profile is double-clicked."""
        self.logger.info("Profile double-click event")
        self._on_edit_profile()

    def _on_profile_list_configure(self, event: tk.Event) -> None:
        """Resize profile list columns to fit available width."""
        try:
            total_width = max(getattr(event, "width", 0), 1)
            name_width = total_width // 2
            ip_width = total_width - name_width
            self.profile_list.column("name", width=name_width)
            self.profile_list.column("ip", width=ip_width)
            self.logger.info(
                "Profile list resized to %s px: name=%s, ip=%s",
                total_width,
                name_width,
                ip_width,
            )
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to resize profile list: %s", exc)

    def _on_tunnel_list_configure(self, event: tk.Event) -> None:
        """Resize tunnel list columns to fit available width."""
        try:
            total_width = max(getattr(event, "width", 0), 1)
            name_width = total_width // 2
            target_width = total_width - name_width
            self.tunnel_list.column("name", width=name_width)
            self.tunnel_list.column("target", width=target_width)
            self.logger.info(
                "Tunnel list resized to %s px: name=%s, target=%s",
                total_width,
                name_width,
                target_width,
            )
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to resize tunnel list: %s", exc)

    def _on_tunnel_select(self, event: tk.Event) -> None:
        """Handle tunnel selection event."""
        selection = event.widget.selection()
        if not selection:
            return
        item_id = selection[0]
        values = event.widget.item(item_id, "values")
        tunnel_name = values[0] if values else ""
        if len(values) >= 2:
            self.logger.info("Tunnel selected: %s -> %s", values[0], values[1])
        elif values:
            self.logger.info("Tunnel selected: %s", tunnel_name)

        try:
            profile_sel = self.profile_list.selection()
            profile_name = (
                self.profile_list.item(profile_sel[0], "values")[0]
                if profile_sel
                else ""
            )
            profiles = load_profiles()
            profile = next((p for p in profiles if p.get("name") == profile_name), None)
            tunnel = None
            if profile:
                tunnel = next(
                    (t for t in profile.get("tunnels", []) if t.get("name") == tunnel_name),
                    None,
                )
            if profile and tunnel:
                cmd = (
                    f"ssh -i {profile.get('ssh_key', '')} -p {tunnel.get('ssh_port')} "
                    f"-L {tunnel.get('local_port')}:{tunnel.get('remote_host')}:"
                    f"{tunnel.get('remote_port')} "
                    f"{tunnel.get('username')}@{tunnel.get('ssh_host')}"
                )
                dns = ", ".join(tunnel.get("dns_names", []))
                info_lines = [f"Tunnel: {tunnel_name}", f"Command: {cmd}"]
                if dns:
                    info_lines.append(f"DNS: {dns}")
                self.status_text.delete("1.0", tk.END)
                self.status_text.insert(tk.END, "\n".join(info_lines))
                self.logger.info(
                    "Displayed tunnel info for '%s' in profile '%s'",
                    tunnel_name,
                    profile_name,
                )
            else:
                self.status_text.delete("1.0", tk.END)
                self.status_text.insert(tk.END, "<TUNNEL_INFO_AND_STATUS>")
                self.logger.warning(
                    "Failed to display tunnel info: profile '%s' or tunnel '%s' not found",
                    profile_name,
                    tunnel_name,
                )
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to display tunnel info: %s", exc)

    def _on_tunnel_double_click(self, event: tk.Event) -> None:  # pragma: no cover - GUI event
        """Open the tunnel edit dialog when a tunnel is double-clicked."""
        self.logger.info("Tunnel double-click event")
        self._on_edit_tunnel()

    def _load_tunnels(self, profile_name: str) -> None:
        """Populate the tunnel list for the given profile."""
        # Clear existing rows before loading new ones
        self.tunnel_list.delete(*self.tunnel_list.get_children())
        try:
            profiles = load_profiles()
            profile = next((p for p in profiles if p.get("name") == profile_name), None)
            tunnels = profile.get("tunnels", []) if profile else []
            for tunnel in tunnels:
                target = f"{tunnel.get('remote_host', '')}:{tunnel.get('remote_port', '')}"
                self.tunnel_list.insert("", tk.END, values=(tunnel.get("name", ""), target))
            self.logger.info(
                "Loaded %d tunnels for profile '%s'", len(tunnels), profile_name
            )
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception(
                "Failed to load tunnels for profile '%s': %s", profile_name, exc
            )

    def _load_profiles_into_list(self) -> None:
        """Populate the profiles table from stored profiles."""
        try:
            profiles = load_profiles()
            for profile in profiles:
                self.profile_list.insert(
                    "",
                    tk.END,
                    values=(profile["name"], profile["ip"]),
                )
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to load profiles: %s", exc)

    def _on_new_profile(self) -> None:
        """Triggered when the 'New Profile' button is pressed."""
        self.logger.info("New profile creation requested")
        try:
            profiles = load_profiles()
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to load profiles for dialog: %s", exc)
            messagebox.showerror("Error", "Failed to load profiles")
            return

        dialog = ProfileDialog(self.root, profiles)
        if not getattr(dialog, "result", None):
            self.logger.info("Profile creation cancelled by user")
            return
        name, key_path, ip = dialog.result
        try:
            profile = create_profile(name, key_path, ip)
            self.profile_list.insert(
                "",
                tk.END,
                values=(profile["name"], profile["ip"]),
            )
            self.logger.info("Profile '%s' created", profile["name"])
        except Exception as exc:
            self.logger.exception("Failed to create profile: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_edit_profile(self) -> None:
        """Triggered when the 'Edit Profile' button is pressed."""
        self.logger.info("Profile edit requested")
        selection = self.profile_list.selection()
        if not selection:
            messagebox.showwarning("No selection", "Please select a profile to edit.")
            self.logger.info("Profile edit cancelled: no profile selected")
            return
        item_id = selection[0]
        values = self.profile_list.item(item_id, "values")
        name = values[0]
        try:
            profiles = load_profiles()
            profile = next((p for p in profiles if p.get("name") == name), None)
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to load profiles for edit: %s", exc)
            messagebox.showerror("Error", "Failed to load profiles")
            return
        if profile is None:
            messagebox.showerror("Error", f"Profile '{name}' not found")
            self.logger.warning("Profile '%s' not found during edit", name)
            return
        dialog = ProfileDialog(self.root, profiles, profile)
        if not getattr(dialog, "result", None):
            self.logger.info("Profile edit cancelled by user")
            return
        new_name, key_path, ip = dialog.result
        try:
            updated = update_profile(name, new_name, key_path, ip)
            self.profile_list.item(
                item_id, values=(updated["name"], updated["ip"])
            )
            self.logger.info("Profile '%s' updated", updated["name"])
        except Exception as exc:
            self.logger.exception("Failed to update profile: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_delete_profile(self) -> None:
        """Triggered when the 'Delete Profile' button is pressed."""
        self.logger.info("Profile deletion requested")
        selection = self.profile_list.selection()
        if not selection:
            messagebox.showwarning("No selection", "Please select a profile to delete.")
            self.logger.info("Profile deletion cancelled: no profile selected")
            return
        item_id = selection[0]
        values = self.profile_list.item(item_id, "values")
        name = values[0]
        if not messagebox.askyesno("Confirm", f"Delete profile '{name}'?"):
            self.logger.info("Profile deletion cancelled by user")
            return
        try:
            removed = delete_profile(name)
            if removed:
                self.profile_list.delete(item_id)
                self.logger.info("Profile '%s' deleted", name)
            else:
                self.logger.warning("Profile '%s' not found during deletion", name)
        except Exception as exc:
            self.logger.exception("Failed to delete profile: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_new_tunnel(self) -> None:
        """Triggered when the 'New Tunnel' button is pressed."""
        self.logger.info("New tunnel creation requested")
        selection = self.profile_list.selection()
        if not selection:
            messagebox.showwarning(
                "No profile", "Please select a profile to add a tunnel."
            )
            self.logger.info("Tunnel creation cancelled: no profile selected")
            return
        item_id = selection[0]
        values = self.profile_list.item(item_id, "values")
        profile_name = values[0]
        try:
            profiles = load_profiles()
            profile = next((p for p in profiles if p.get("name") == profile_name), None)
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to load profiles for tunnel dialog: %s", exc)
            messagebox.showerror("Error", "Failed to load profiles")
            return
        existing = profile.get("tunnels", []) if profile else []
        dialog = TunnelDialog(self.root, existing)
        if not getattr(dialog, "result", None):
            self.logger.info("Tunnel creation cancelled by user")
            return
        (
            name,
            ssh_host,
            username,
            local_port,
            host,
            remote_port,
            ssh_port,
            dns_names,
        ) = dialog.result
        try:
            tunnel = add_tunnel(
                profile_name,
                name,
                ssh_host,
                username,
                local_port,
                host,
                remote_port,
                ssh_port,
                dns_names,
            )
            target = f"{host}:{remote_port}"
            self.tunnel_list.insert("", tk.END, values=(tunnel["name"], target))
            self.logger.info(
                "Tunnel '%s' added to profile '%s' with DNS '%s'",
                name,
                profile_name,
                ", ".join(dns_names),
            )
        except Exception as exc:
            self.logger.exception("Failed to add tunnel: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_edit_tunnel(self) -> None:
        """Triggered when the 'Edit Tunnel' button is pressed."""
        self.logger.info("Tunnel edit requested")
        profile_sel = self.profile_list.selection()
        if not profile_sel:
            messagebox.showwarning(
                "No profile", "Please select a profile to edit its tunnel."
            )
            self.logger.info("Tunnel edit cancelled: no profile selected")
            return
        profile_name = self.profile_list.item(profile_sel[0], "values")[0]
        tunnel_sel = self.tunnel_list.selection()
        if not tunnel_sel:
            messagebox.showwarning(
                "No selection", "Please select a tunnel to edit."
            )
            self.logger.info("Tunnel edit cancelled: no tunnel selected")
            return
        item_id = tunnel_sel[0]
        tunnel_name = self.tunnel_list.item(item_id, "values")[0]
        try:
            profiles = load_profiles()
            profile = next((p for p in profiles if p.get("name") == profile_name), None)
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to load profiles for tunnel edit: %s", exc)
            messagebox.showerror("Error", "Failed to load profiles")
            return
        if profile is None:
            messagebox.showerror("Error", f"Profile '{profile_name}' not found")
            self.logger.warning(
                "Profile '%s' not found during tunnel edit", profile_name
            )
            return
        tunnels = profile.get("tunnels", [])
        tunnel = next((t for t in tunnels if t.get("name") == tunnel_name), None)
        if tunnel is None:
            messagebox.showerror(
                "Error", f"Tunnel '{tunnel_name}' not found in profile '{profile_name}'"
            )
            self.logger.warning(
                "Tunnel '%s' not found during edit for profile '%s'",
                tunnel_name,
                profile_name,
            )
            return
        dialog = TunnelDialog(self.root, tunnels, tunnel)
        if not getattr(dialog, "result", None):
            self.logger.info("Tunnel edit cancelled by user")
            return
        (
            new_name,
            ssh_host,
            username,
            local_port,
            host,
            remote_port,
            ssh_port,
            dns_names,
        ) = dialog.result
        try:
            update_tunnel(
                profile_name,
                tunnel_name,
                new_name,
                ssh_host,
                username,
                local_port,
                host,
                remote_port,
                ssh_port,
                dns_names,
            )
            target = f"{host}:{remote_port}"
            self.tunnel_list.item(item_id, values=(new_name, target))
            self.logger.info(
                "Tunnel '%s' updated in profile '%s' with DNS '%s'",
                tunnel_name,
                profile_name,
                ", ".join(dns_names),
            )
        except Exception as exc:
            self.logger.exception("Failed to update tunnel: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_delete_tunnel(self) -> None:
        """Triggered when the 'Delete Tunnel' button is pressed."""
        self.logger.info("Tunnel deletion requested")
        profile_sel = self.profile_list.selection()
        if not profile_sel:
            messagebox.showwarning(
                "No profile", "Please select a profile to delete its tunnel."
            )
            self.logger.info("Tunnel deletion cancelled: no profile selected")
            return
        profile_name = self.profile_list.item(profile_sel[0], "values")[0]
        tunnel_sel = self.tunnel_list.selection()
        if not tunnel_sel:
            messagebox.showwarning(
                "No selection", "Please select a tunnel to delete."
            )
            self.logger.info("Tunnel deletion cancelled: no tunnel selected")
            return
        item_id = tunnel_sel[0]
        tunnel_name = self.tunnel_list.item(item_id, "values")[0]
        if not messagebox.askyesno("Confirm", f"Delete tunnel '{tunnel_name}'?"):
            self.logger.info("Tunnel deletion cancelled by user")
            return
        try:
            removed = delete_tunnel(profile_name, tunnel_name)
            if removed:
                self.tunnel_list.delete(item_id)
                self.logger.info(
                    "Tunnel '%s' deleted from profile '%s'",
                    tunnel_name,
                    profile_name,
                )
            else:
                self.logger.warning(
                    "Tunnel '%s' not found during deletion for profile '%s'",
                    tunnel_name,
                    profile_name,
                )
        except Exception as exc:
            self.logger.exception("Failed to delete tunnel: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_start_tunnel(self) -> None:
        """Start the selected SSH tunnel."""
        self.logger.info("Tunnel start requested")
        profile_sel = self.profile_list.selection()
        if not profile_sel:
            messagebox.showwarning(
                "No profile", "Please select a profile to start its tunnel.",
            )
            self.logger.info("Tunnel start cancelled: no profile selected")
            return
        tunnel_sel = self.tunnel_list.selection()
        if not tunnel_sel:
            messagebox.showwarning(
                "No selection", "Please select a tunnel to start.",
            )
            self.logger.info("Tunnel start cancelled: no tunnel selected")
            return
        profile_name = self.profile_list.item(profile_sel[0], "values")[0]
        tunnel_name = self.tunnel_list.item(tunnel_sel[0], "values")[0]
        key = (profile_name, tunnel_name)
        forwarder = self.active_tunnels.get(key)
        if forwarder and forwarder.is_active:
            messagebox.showwarning(
                "Running", f"Tunnel '{tunnel_name}' is already running.",
            )
            self.logger.info(
                "Tunnel '%s' already running for profile '%s'", tunnel_name, profile_name
            )
            return
        try:
            profiles = load_profiles()
            profile = next((p for p in profiles if p.get("name") == profile_name), None)
            tunnel = None
            if profile:
                tunnel = next(
                    (t for t in profile.get("tunnels", []) if t.get("name") == tunnel_name),
                    None,
                )
            if not profile or not tunnel:
                raise ValueError(
                    f"Profile '{profile_name}' or tunnel '{tunnel_name}' not found"
                )
            bind_ip = profile.get("ip")
            if not bind_ip:
                raise ValueError(f"Profile '{profile_name}' has no IP address")
            forwarder = SSHTunnelForwarder(
                ssh_address_or_host=(tunnel.get("ssh_host"), int(tunnel.get("ssh_port"))),
                ssh_username=tunnel.get("username"),
                ssh_pkey=profile.get("ssh_key"),
                # Accept any server fingerprint by not providing host key
                ssh_host_key=None,
                host_pkey_directories=[],
                allow_agent=False,
                ssh_config_file=None,
                # Bind the local side to the profile's dedicated IP
                local_bind_address=(bind_ip, int(tunnel.get("local_port"))),
                remote_bind_address=(tunnel.get("remote_host"), int(tunnel.get("remote_port"))),
            )
            forwarder.start()
            self.active_tunnels[key] = forwarder
            self.logger.info(
                "Started tunnel '%s' for profile '%s'", tunnel_name, profile_name
            )
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to start tunnel: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_stop_tunnel(self) -> None:
        """Stop the selected SSH tunnel if running."""
        self.logger.info("Tunnel stop requested")
        profile_sel = self.profile_list.selection()
        if not profile_sel:
            messagebox.showwarning(
                "No profile", "Please select a profile to stop its tunnel.",
            )
            self.logger.info("Tunnel stop cancelled: no profile selected")
            return
        tunnel_sel = self.tunnel_list.selection()
        if not tunnel_sel:
            messagebox.showwarning(
                "No selection", "Please select a tunnel to stop.",
            )
            self.logger.info("Tunnel stop cancelled: no tunnel selected")
            return
        profile_name = self.profile_list.item(profile_sel[0], "values")[0]
        tunnel_name = self.tunnel_list.item(tunnel_sel[0], "values")[0]
        key = (profile_name, tunnel_name)
        forwarder = self.active_tunnels.get(key)
        if not forwarder or not forwarder.is_active:
            messagebox.showwarning(
                "Not running", f"Tunnel '{tunnel_name}' is not running.",
            )
            self.logger.info(
                "Tunnel '%s' not running for profile '%s'", tunnel_name, profile_name
            )
            return
        try:
            forwarder.stop()
            del self.active_tunnels[key]
            self.logger.info(
                "Stopped tunnel '%s' for profile '%s'", tunnel_name, profile_name
            )
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to stop tunnel: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_manage_ssh_key(self) -> None:
        """Triggered when the 'Manage SSH Key' button is pressed."""
        self.logger.info("SSH key management requested")
        try:
            SSHKeyManager(self.root)
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to open SSH key manager: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_settings(self) -> None:
        """Triggered when the 'Settings' button is pressed."""
        self.logger.info("Settings requested")
        messagebox.showinfo("Info", "Settings functionality not yet implemented.")

    def _on_pane_resize(self, event: tk.Event) -> None:
        """Log and persist pane positions after user resizes the interface."""
        try:
            pane_count = len(self.top_pane.panes())
            coords = [self.top_pane.sash_coord(i)[0] for i in range(pane_count - 1)]
            self.logger.info("Pane resized; sash coordinates: %s", coords)
            save_pane_layout(coords)
        except Exception as exc:
            self.logger.exception("Failed to log pane resize: %s", exc)

    def run(self) -> None:
        """Run the Tkinter main event loop."""
        self.logger.info("Application started")
        try:
            self.root.mainloop()
        except Exception as exc:  # Catch-all to prevent crashes
            self.logger.exception("Unexpected error: %s", exc)
            messagebox.showerror("Error", str(exc))


def main() -> None:
    """Entry point for running the application."""
    cfg = configparser.ConfigParser()
    try:
        cfg.read('config.ini')
    except Exception as exc:  # pragma: no cover - difficult to trigger
        print(f"Failed to read configuration: {exc}")
        return

    root = tk.Tk()
    root.title(cfg.get('ui', 'title', fallback='Lighthouse'))
    root.geometry(geometry_from_config(cfg))
    app = LighthouseApp(root, cfg)
    app.run()


if __name__ == '__main__':
    main()
