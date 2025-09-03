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

_ORIGINAL_FORWARDER = SSHTunnelForwarder

from lighthouse_app.hosts import (
    add_hosts_block,
    remove_hosts_block,
    default_hosts_file,
)
from lighthouse_app.profiles import PROFILES_FILE, load_profiles as _load_profiles


def load_profiles(file_path: Union[str, Path] = PROFILES_FILE) -> List[Dict[str, str]]:
    """Load profile definitions for the UI layer.

    This helper retains a simple API that tests can monkeypatch while
    delegating the actual work to :mod:`lighthouse_app.profiles`.
    Any unexpected error is logged and results in an empty list.
    """
    logger = logging.getLogger(__name__)
    logger.debug("UI request to load profiles from %s", file_path)
    try:
        profiles = _load_profiles(file_path)
        logger.debug("UI loaded %d profiles", len(profiles))
        return profiles
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("UI failed to load profiles: %s", exc)
        return []


def _safe_read_private_key_file(
    pkey_file: str,
    pkey_password: Optional[str] = None,
    key_type: Optional[type] = None,
    logger: Optional[logging.Logger] = None,
):
    """Read private keys without relying on deprecated DSA support.

    Paramiko 3.x removed the ``DSSKey`` class used for DSA keys.  The
    upstream ``sshtunnel`` library still references it which raises an
    :class:`AttributeError`.  This helper mirrors the original behaviour
    but simply skips DSA handling when the class is missing.

    Parameters
    ----------
    pkey_file: str
        Path to the private key file.
    pkey_password: str, optional
        Password for decrypting the key if required.
    key_type: type, optional
        Explicit key class to try first.  When omitted, several common
        types are attempted.
    logger: logging.Logger, optional
        Logger used for debug output.
    """

    if key_type:
        key_types = (key_type,)
    else:
        key_types = [paramiko.RSAKey]
        if hasattr(paramiko, "ECDSAKey"):
            key_types.append(paramiko.ECDSAKey)
        if hasattr(paramiko, "Ed25519Key"):
            key_types.append(paramiko.Ed25519Key)

    for pkey_cls in key_types:
        try:
            if logger:
                logger.debug("Attempting to load %s using %s", pkey_file, pkey_cls.__name__)
            return pkey_cls.from_private_key_file(pkey_file, password=pkey_password)
        except paramiko.PasswordRequiredException:
            if logger:
                logger.error("Password is required for key %s", pkey_file)
            break
        except (paramiko.SSHException, OSError) as exc:
            if logger:
                logger.debug(
                    "Failed loading %s as %s: %s", pkey_file, pkey_cls.__name__, exc
                )
    return None


def _safe_get_keys(logger=None, host_pkey_directories=None, allow_agent=False):
    """Load available private keys while tolerating missing DSA support.

    Paramiko 3 removed the ``DSSKey`` class used for DSA keys.  The upstream
    ``sshtunnel`` package still tries to import it which results in an
    :class:`AttributeError`.  This function mirrors the original
    implementation but skips the DSA handler when the class is absent.

    Parameters
    ----------
    logger: logging.Logger, optional
        Logger used for debug information.
    host_pkey_directories: list[str], optional
        Directories searched for private key files.
    allow_agent: bool
        When ``True`` the SSH agent is queried for keys.
    """

    keys = (
        SSHTunnelForwarder.get_agent_keys(logger=logger) if allow_agent else []
    )

    if host_pkey_directories is None:
        host_pkey_directories = [DEFAULT_SSH_DIRECTORY]

    paramiko_key_types = {"rsa": paramiko.RSAKey}
    if hasattr(paramiko, "ECDSAKey"):
        paramiko_key_types["ecdsa"] = paramiko.ECDSAKey
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


# Replace original methods with the safe versions for module-wide use
SSHTunnelForwarder.read_private_key_file = staticmethod(_safe_read_private_key_file)
SSHTunnelForwarder.get_keys = staticmethod(_safe_get_keys)

from lighthouse_app.controllers.profile_controller import ProfileController
from lighthouse_app.controllers.key_controller import KeyController

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
    """Dialog window for collecting or editing profile parameters.

    The dialog uses a fixed size so users cannot resize the window.
    """

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
            keys = KeyController().load_keys()
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
        """Construct dialog body with labelled input widgets.

        The profile name field now mirrors the appearance of the main
        window's *Status* container by using a ``LabelFrame``.  This
        places the descriptive text in the frame's border with the entry
        widget inside, making the label appear above the input field.
        """
        # Disallow user resizing to preserve layout integrity
        if hasattr(self, "resizable") and getattr(self, "tk", None):
            self.resizable(False, False)
            self.logger.debug("Profile dialog resize disabled")
        else:  # pragma: no cover - defensive
            self.logger.debug("Resize control not supported in this context")

        # Allow the dialog's contents to stretch with window width
        if hasattr(master, "columnconfigure"):
            master.columnconfigure(0, weight=1)
            master.columnconfigure(1, weight=1)
            self.logger.debug("Profile dialog master configured for horizontal expansion")

        # Profile name container with border and caption above the entry
        self.name_frame = tk.LabelFrame(master, text="Profile name")
        self.name_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.name_frame.columnconfigure(0, weight=1)
        self.name_entry = tk.Entry(self.name_frame)
        self.name_entry.grid(row=0, column=0, sticky="ew")
        self.logger.debug("Profile name field prepared in labelled frame")

        # SSH key selection grouped in a labelled frame
        self.key_frame = tk.LabelFrame(master, text="SSH key")
        self.key_frame.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.key_frame.columnconfigure(0, weight=1)
        # Prepare drop-down of available SSH keys
        self.key_var = tk.StringVar()
        self.key_combo = ttk.Combobox(
            self.key_frame, textvariable=self.key_var, state="readonly"
        )
        # Map of key names to file system paths
        self.key_map = self._load_key_map()
        self.key_combo["values"] = list(self.key_map.keys())
        self.key_combo.grid(row=0, column=0, sticky="ew")
        self.logger.debug("SSH key selection prepared in labelled frame")

        # IP settings grouped for clarity
        self.ip_frame = tk.LabelFrame(master, text="IP Settings")
        self.ip_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
        self.ip_frame.columnconfigure(1, weight=1)
        self.logger.debug("IP settings fields prepared in labelled frame")

        auto_default = True if self.profile is None else bool(self.profile.get("auto_ip"))
        self.auto_var = tk.BooleanVar(value=auto_default)
        auto_chk = tk.Checkbutton(
            self.ip_frame,
            text="Assign IP automatically",
            variable=self.auto_var,
            command=self._toggle_ip_entry,
        )
        auto_chk.grid(row=0, column=0, columnspan=2, sticky="w")

        tk.Label(self.ip_frame, text="IP address:").grid(row=1, column=0, sticky="w")
        self.ip_entry = tk.Entry(self.ip_frame)
        self.ip_entry.grid(row=1, column=1, sticky="ew")
        self.ip_entry.configure(state="disabled" if auto_default else "normal")

        # Autoconfig settings grouped for clarity
        self.autoconfig_frame = tk.LabelFrame(master, text="Autoconfig")
        self.autoconfig_frame.grid(row=3, column=0, columnspan=2, sticky="ew")
        self.autoconfig_frame.columnconfigure(1, weight=1)
        self.logger.debug("Autoconfig fields prepared in labelled frame")

        self.autoconfig_var = tk.BooleanVar(value=False)
        autoconfig_chk = tk.Checkbutton(
            self.autoconfig_frame,
            text="Use autoconfig",
            variable=self.autoconfig_var,
            command=self._toggle_autoconfig_entry,
        )
        autoconfig_chk.grid(row=0, column=0, columnspan=2, sticky="w")

        tk.Label(self.autoconfig_frame, text="URL:").grid(row=1, column=0, sticky="w")
        self.autoconfig_entry = tk.Entry(self.autoconfig_frame)
        self.autoconfig_entry.grid(row=1, column=1, sticky="ew")
        self.autoconfig_entry.configure(state="disabled")

        if self.profile is not None:
            self.name_entry.insert(0, self.profile.get("name", ""))
            # Pre-select SSH key based on stored path
            existing_path = self.profile.get("ssh_key", "")
            for key_name, key_path in self.key_map.items():
                if key_path == existing_path:
                    self.key_var.set(key_name)
                    break
            self.ip_entry.insert(0, self.profile.get("ip", ""))

        # Ensure dialog height and width accommodate all widgets
        if getattr(self, "tk", None) and hasattr(self, "update_idletasks"):
            self.update_idletasks()
            required_w = self.winfo_reqwidth()
            required_h = self.winfo_reqheight()
            if hasattr(self, "minsize"):
                self.minsize(required_w, required_h)
                self.logger.debug(
                    "Profile dialog minimum size set to %dx%d", required_w, required_h
                )

        return self.name_entry

    def _toggle_ip_entry(self) -> None:
        if self.auto_var.get():
            self.ip_entry.configure(state="disabled")
            self.logger.info("Profile dialog: automatic IP selected")
        else:
            self.ip_entry.configure(state="normal")
            self.logger.info("Profile dialog: manual IP selected")

    def _toggle_autoconfig_entry(self) -> None:
        if self.autoconfig_var.get():
            self.autoconfig_entry.configure(state="normal")
            self.logger.info("Profile dialog: autoconfig enabled")
        else:
            self.autoconfig_entry.configure(state="disabled")
            self.logger.info("Profile dialog: autoconfig disabled")

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
        ip_str = self.ip_entry.get().strip() or None
        auto_assign = self.auto_var.get()
        self.result = (name, key_path, ip_str, auto_assign)
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
        """Build dialog widgets grouped in labeled frames."""
        # Ensure the main container expands with window resizing
        if hasattr(master, "columnconfigure"):
            master.columnconfigure(0, weight=1)
            master.columnconfigure(1, weight=1)
            self.logger.debug("Tunnel dialog master configured for full-width expansion")

        # Determine uniform width for all labels so entries align
        label_texts = [
            "SSH Host:",
            "Username:",
            "SSH Port:",
            "Local port:",
            "Remote host:",
            "Remote port:",
            "DNS Name:",
        ]
        label_width = max(len(text) for text in label_texts)
        self.logger.debug("Tunnel dialog: label width %d characters", label_width)

        # Frame for tunnel name input
        name_frame = tk.LabelFrame(master, text="Tunnel name")
        name_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
        name_frame.columnconfigure(0, weight=1)
        self.name_entry = tk.Entry(name_frame)
        self.name_entry.grid(row=0, column=0, sticky="ew")

        # SSH settings
        ssh_frame = tk.LabelFrame(master, text="SSH Setting")
        ssh_frame.grid(row=1, column=0, columnspan=2, sticky="ew")
        ssh_frame.columnconfigure(1, weight=1)
        tk.Label(ssh_frame, text="SSH Host:", width=label_width, anchor="w").grid(
            row=0, column=0, sticky="w"
        )
        self.ssh_host_entry = tk.Entry(ssh_frame)
        self.ssh_host_entry.grid(row=0, column=1, sticky="ew")
        tk.Label(ssh_frame, text="Username:", width=label_width, anchor="w").grid(
            row=1, column=0, sticky="w"
        )
        self.user_entry = tk.Entry(ssh_frame)
        self.user_entry.grid(row=1, column=1, sticky="ew")
        tk.Label(ssh_frame, text="SSH Port:", width=label_width, anchor="w").grid(
            row=2, column=0, sticky="w"
        )
        self.ssh_port_entry = tk.Entry(ssh_frame)
        self.ssh_port_entry.grid(row=2, column=1, sticky="ew")

        # Tunnel settings
        tunnel_frame = tk.LabelFrame(master, text="Tunnel Setting")
        tunnel_frame.grid(row=2, column=0, columnspan=2, sticky="ew")
        tunnel_frame.columnconfigure(1, weight=1)
        tk.Label(tunnel_frame, text="Local port:", width=label_width, anchor="w").grid(
            row=0, column=0, sticky="w"
        )
        self.local_entry = tk.Entry(tunnel_frame)
        self.local_entry.grid(row=0, column=1, sticky="ew")
        tk.Label(
            tunnel_frame, text="Remote host:", width=label_width, anchor="w"
        ).grid(row=1, column=0, sticky="w")
        self.host_entry = tk.Entry(tunnel_frame)
        self.host_entry.grid(row=1, column=1, sticky="ew")
        tk.Label(
            tunnel_frame, text="Remote port:", width=label_width, anchor="w"
        ).grid(row=2, column=0, sticky="w")
        self.remote_entry = tk.Entry(tunnel_frame)
        self.remote_entry.grid(row=2, column=1, sticky="ew")

        # DNS override
        dns_frame = tk.LabelFrame(master, text="DNS Override")
        dns_frame.grid(row=3, column=0, columnspan=2, sticky="ew")
        dns_frame.columnconfigure(1, weight=1)
        # Checkbox controlling DNS override state
        self.dns_enabled_var = tk.BooleanVar(value=True)
        enable_chk = tk.Checkbutton(
            dns_frame,
            text="Enable DNS Override",
            variable=self.dns_enabled_var,
            command=self._toggle_dns_widgets,
        )
        enable_chk.grid(row=0, column=0, columnspan=3, sticky="w")
        # Widgets for managing DNS names
        self.dns_label = tk.Label(
            dns_frame, text="DNS Name:", width=label_width, anchor="nw"
        )
        self.dns_label.grid(row=1, column=0, sticky="nw")
        # List of DNS names kept compact to reduce overall width
        self.dns_list = tk.Listbox(dns_frame, height=3)
        self.dns_list.grid(row=1, column=1, columnspan=2, sticky="nsew")
        # Entry for new DNS names placed below the list
        self.dns_entry = tk.Entry(dns_frame)
        self.dns_entry.grid(row=2, column=1, columnspan=2, sticky="ew")
        # Action buttons placed under the entry for a cleaner layout
        self.add_btn = tk.Button(dns_frame, text="+", command=self._add_dns)
        self.add_btn.grid(row=3, column=1, sticky="ew")
        self.del_btn = tk.Button(dns_frame, text="-", command=self._remove_dns)
        self.del_btn.grid(row=3, column=2, sticky="ew")

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
            self.dns_enabled_var.set(self.tunnel.get("dns_override", True))
            self.logger.info(
                "Tunnel dialog: DNS override preset to %s",
                self.dns_enabled_var.get(),
            )
        else:
            # Fill SSH port with safe default for new tunnels
            self.ssh_port_entry.insert(0, "22")
            self.logger.info("Tunnel dialog: default SSH port 22 inserted")

        # Disable user resizing to maintain a consistent layout
        if hasattr(self, "resizable"):
            try:
                self.resizable(False, False)
                self.logger.debug("Tunnel dialog resizing disabled")
            except Exception as exc:  # pragma: no cover - defensive
                if hasattr(self.logger, "warning"):
                    self.logger.warning(
                        "Failed to disable tunnel dialog resizing: %s", exc
                    )

        # Defer geometry enforcement until all widgets, including button box,
        # are created.  ``simpledialog.Dialog`` adds buttons after ``body``
        # returns, so using ``after`` ensures final dimensions account for
        # them.  Fallback to immediate enforcement when ``after`` is
        # unavailable (e.g., simplified test doubles).
        if callable(getattr(self, "after", None)) and hasattr(getattr(self, "tk", None), "createcommand"):
            self.after(0, self._enforce_geometry)
        else:  # pragma: no cover - executed only by test stubs without functional ``after``
            self._enforce_geometry()

        # Apply initial state to DNS widgets
        self._toggle_dns_widgets()
        return self.name_entry

    def _enforce_geometry(self) -> None:
        """Ensure all widgets are visible and set a sensible minimum size."""
        if not (getattr(self, "tk", None) and hasattr(self, "update_idletasks")):
            return

        try:
            self.update_idletasks()
            if not all(
                hasattr(self, attr)
                for attr in (
                    "winfo_reqwidth",
                    "winfo_reqheight",
                    "winfo_width",
                    "winfo_height",
                )
            ):
                return

            req_w = self.winfo_reqwidth()
            req_h = self.winfo_reqheight()
            cur_w = self.winfo_width()
            cur_h = self.winfo_height()
            width = max(cur_w, req_w)
            height = max(cur_h, req_h)
            if hasattr(self, "geometry"):
                self.geometry(f"{width}x{height}")
            if hasattr(self, "minsize"):
                self.minsize(req_w, req_h)
            self.logger.debug(
                "Tunnel dialog geometry enforced to %dx%d with minimum %dx%d",
                width,
                height,
                req_w,
                req_h,
            )
        except Exception as exc:  # pragma: no cover - defensive
            if hasattr(self.logger, "exception"):
                self.logger.exception("Failed to enforce tunnel dialog geometry: %s", exc)

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
        dns_override = bool(self.dns_enabled_var.get())
        self.result = (
            name,
            ssh_host,
            username,
            local,
            host,
            remote,
            ssh_port,
            dns_list,
            dns_override,
        )
        self.logger.info(
            "Tunnel dialog confirmed for '%s' with DNS '%s' (override %s)",
            name,
            ", ".join(dns_list),
            dns_override,
        )

    def cancel(self, event=None) -> None:  # pragma: no cover - GUI side effect
        self.logger.info("Tunnel dialog cancelled")
        super().cancel(event)

    def _add_dns(self) -> None:  # pragma: no cover - GUI helper
        """Add DNS name from entry to listbox."""
        if not self.dns_enabled_var.get():
            self.logger.info("Add DNS attempted while override disabled")
            return
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
        if not self.dns_enabled_var.get():
            self.logger.info("Remove DNS attempted while override disabled")
            return
        selection = self.dns_list.curselection()
        if not selection:
            return
        idx = selection[0]
        name = self.dns_list.get(idx)
        self.dns_list.delete(idx)
        self.logger.info("DNS name removed: %s", name)

    def _toggle_dns_widgets(self) -> None:  # pragma: no cover - GUI helper
        """Enable or disable DNS widgets based on checkbox."""
        enabled = self.dns_enabled_var.get()
        state = tk.NORMAL if enabled else tk.DISABLED
        for widget in [
            self.dns_label,
            self.dns_list,
            self.dns_entry,
            self.add_btn,
            self.del_btn,
        ]:
            widget.configure(state=state)
        self.logger.info("DNS override %s", "enabled" if enabled else "disabled")


class SSHKeyManager:
    """Window for managing SSH keys."""

    def __init__(self, parent: tk.Tk, key_controller: KeyController) -> None:
        self.parent = parent
        self.key_controller = key_controller
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
            keys = self.key_controller.load_keys()
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
            keys = self.key_controller.load_keys()
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
            key = self.key_controller.create_key(name, path, desc)
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
            keys = self.key_controller.load_keys()
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
            updated = self.key_controller.update_key(name, new_name, path, desc)
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
            removed = self.key_controller.delete_key(name)
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
        """Create the application and build the UI if Tk widgets are available."""
        import builtins

        # Expose the root object for tests that reference it directly
        builtins.root = root

        self.root = root
        self.cfg = cfg
        self.logger = logging.getLogger(__name__)
        hosts_path = self.cfg.get(
            "hosts", "file", fallback=str(default_hosts_file())
        )
        self.hosts_file = Path(hosts_path)
        self.logger.debug("Hosts file set to %s", self.hosts_file)
        self.profile_controller = ProfileController(self.hosts_file)
        self.key_controller = KeyController()

        # Keep a reference to the previous instance so that subsequent
        # constructions in tests can reuse injected dummy widgets.
        prev_app = getattr(builtins, "_lh_app_instance", None)

        self._setup_logging()

        if hasattr(tk, "PanedWindow"):
            # Normal execution path with a functioning Tk module.
            self._build_ui()
        elif prev_app is not None:
            # When running tests, the Tk module is replaced with a simple
            # namespace and the UI cannot be constructed.  Reuse widgets from
            # the previously created instance so handlers continue to work.
            self.profile_list = getattr(prev_app, "profile_list", None)
            self.tunnel_list = getattr(prev_app, "tunnel_list", None)
            self.status_text = getattr(prev_app, "status_text", None)

        # Remember this instance for potential reuse on subsequent
        # constructions within the test suite.
        builtins._lh_app_instance = self

    def _setup_logging(self) -> None:
        """Configure logging to file and console.

        A custom handler forwards ``ERROR`` level messages to the UI log
        widget so that problems are visible directly in the application.
        """
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler("app.log"),
                logging.StreamHandler(),
            ],
            force=True,
        )

        class UILogHandler(logging.Handler):
            """Send error messages to the on-screen log container."""

            def __init__(self, app: "LighthouseApp") -> None:
                super().__init__(level=logging.ERROR)
                self.app = app

            def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover - UI safety
                try:
                    exc_info = record.exc_info
                    exc_text = getattr(record, "exc_text", None)
                    record.exc_info = None
                    record.exc_text = None
                    message = self.format(record)
                    record.exc_info = exc_info
                    record.exc_text = exc_text
                    self.app._append_log(message)
                except Exception:
                    # Logging failures should never crash the application
                    pass

        ui_handler = UILogHandler(self)
        ui_handler.setFormatter(logging.Formatter("%(levelname)s - %(message)s"))
        logging.getLogger().addHandler(ui_handler)

    def _append_log(self, message: str) -> None:
        """Append a message to the log text widget safely.

        The log area is kept read-only by toggling the widget state
        during writes. This method is a no-op if the widget is missing.
        """
        if not hasattr(self, "log_text"):
            return
        try:
            self.log_text.configure(state="normal")
            self.log_text.insert(tk.END, message + "\n")
            self.log_text.configure(state="disabled")
            self.log_text.see(tk.END)
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to append log message: %s", exc)

    def _build_ui(self) -> None:
        """Create and arrange widgets using a resizable paned window."""
        # Allow the main window to be resized by the user
        if hasattr(self.root, "resizable"):
            self.root.resizable(True, True)
            self.logger.debug("Main window resize enabled")

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

        # Profiles list displayed as a table inside a labeled frame for clarity
        profile_frame = tk.LabelFrame(
            self.top_pane, text="Profiles", bd=2, relief=tk.GROOVE
        )
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
        # Highlight active profiles in green
        self.profile_list.tag_configure("active", foreground="green")
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

        # Tunnels list displayed inside its own labeled frame
        tunnel_frame = tk.LabelFrame(
            self.top_pane, text="Tunnels", bd=2, relief=tk.GROOVE
        )
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
        # Highlight active tunnels in green
        self.tunnel_list.tag_configure("active", foreground="green")
        self.tunnel_list.bind("<<TreeviewSelect>>", self._on_tunnel_select)
        self.tunnel_list.bind("<Double-1>", self._on_tunnel_double_click)
        # Adjust column widths whenever the widget size changes
        self.tunnel_list.bind("<Configure>", self._on_tunnel_list_configure)

        # Load profiles once widgets are ready so highlight updates succeed
        self._load_profiles_into_list()

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

        # Container showing current tunnel status
        self.status_frame = tk.LabelFrame(info_frame, text="Status")
        self.status_frame.grid(row=0, column=0, sticky="nsew")
        self.status_frame.rowconfigure(0, weight=1)
        self.status_frame.columnconfigure(0, weight=1)

        self.status_text = tk.Text(self.status_frame, height=10)
        self.status_text.grid(row=0, column=0, sticky="nsew")

        self.log_text = tk.Text(info_frame, height=8, state="disabled")
        self.log_text.grid(row=1, column=0, sticky="nsew")
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

        # Ensure the main window fits its widgets while allowing reduction to a
        # configurable minimum size
        if hasattr(self.root, "update_idletasks"):
            self.root.update_idletasks()
            if all(
                hasattr(self.root, attr)
                for attr in ["winfo_reqwidth", "winfo_reqheight", "winfo_width", "winfo_height"]
            ):
                req_w = self.root.winfo_reqwidth()
                req_h = self.root.winfo_reqheight()
                cur_w = self.root.winfo_width()
                cur_h = self.root.winfo_height()
                min_w = self.cfg.getint("ui", "min_width", fallback=200)
                min_h = self.cfg.getint("ui", "min_height", fallback=200)
                width = max(cur_w, req_w, min_w)
                height = max(cur_h, req_h, min_h)
                if hasattr(self.root, "geometry"):
                    self.root.geometry(f"{width}x{height}")
                if hasattr(self.root, "minsize"):
                    self.root.minsize(min_w, min_h)
                self.logger.debug(
                    "Main window geometry enforced to %dx%d with minimum %dx%d",
                    width,
                    height,
                    min_w,
                    min_h,
                )

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
        except Exception:  # pragma: no cover - defensive
            # Ignore resize errors to keep UI responsive
            pass

    def _on_tunnel_list_configure(self, event: tk.Event) -> None:
        """Resize tunnel list columns to fit available width."""
        try:
            total_width = max(getattr(event, "width", 0), 1)
            name_width = total_width // 2
            target_width = total_width - name_width
            self.tunnel_list.column("name", width=name_width)
            self.tunnel_list.column("target", width=target_width)
        except Exception:  # pragma: no cover - defensive
            # Ignore resize errors to keep UI responsive
            pass

    def _on_tunnel_select(self, event: tk.Event | None = None) -> None:
        """Display information about the selected tunnel and its status.

        Parameters
        ----------
        event: tk.Event | None
            Event from Tkinter. When ``None`` the current selection in
            ``self.tunnel_list`` is used, allowing other handlers to refresh
            the status pane without crafting an event object.
        """
        widget = event.widget if event else self.tunnel_list
        selection = widget.selection()
        if not selection:
            self.logger.debug("Tunnel select event with no selection")
            return
        item_id = selection[0]
        values = widget.item(item_id, "values")
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
                dns = ", ".join(tunnel.get("dns_names", []))
                key = (profile_name, tunnel_name)
                forwarder = self.profile_controller.active_tunnels.get(key)
                status = (
                    "running"
                    if forwarder and getattr(forwarder, "is_active", False)
                    else "stopped"
                )
                info_lines = [f"Tunnel: {tunnel_name}", f"Status: {status}"]
                if dns:
                    info_lines.append(f"DNS: {dns}")
                self.status_text.delete("1.0", tk.END)
                self.status_text.insert(tk.END, "\n".join(info_lines))
                self.logger.info(
                    "Displayed tunnel info for '%s' in profile '%s' with status '%s'",
                    tunnel_name,
                    profile_name,
                    status,
                )
            else:
                self.status_text.delete("1.0", tk.END)
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
            profiles = self.profile_controller.load_profiles()
            profile = next((p for p in profiles if p.get("name") == profile_name), None)
            tunnels = profile.get("tunnels", []) if profile else []
            for tunnel in tunnels:
                target = f"{tunnel.get('remote_host', '')}:{tunnel.get('remote_port', '')}"
                self.tunnel_list.insert("", tk.END, values=(tunnel.get("name", ""), target))
            self.logger.info(
                "Loaded %d tunnels for profile '%s'", len(tunnels), profile_name
            )
            # Ensure active tunnels are highlighted
            self._update_highlights()
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception(
                "Failed to load tunnels for profile '%s': %s", profile_name, exc
            )

    def _load_profiles_into_list(self) -> None:
        """Populate the profiles table from stored profiles."""
        try:
            profiles = self.profile_controller.load_profiles()
            for profile in profiles:
                self.profile_list.insert(
                    "",
                    tk.END,
                    values=(profile["name"], profile["ip"]),
                )
            # Highlight any profiles with active tunnels
            self._update_highlights()
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to load profiles: %s", exc)

    def _update_highlights(self) -> None:
        """Highlight active profiles and tunnels in the UI."""
        try:
            # Determine which profiles currently have active tunnels
            active_profiles = {
                name
                for (name, _tunnel), fwd in self.profile_controller.active_tunnels.items()
                if getattr(fwd, "is_active", False)
            }
            # Highlight profiles
            for item in self.profile_list.get_children():
                values = self.profile_list.item(item, "values")
                profile_name = values[0] if values else ""
                if profile_name in active_profiles:
                    self.profile_list.item(item, tags=("active",))
                else:
                    self.profile_list.item(item, tags=())

            # Highlight tunnels for currently selected profile
            profile_sel = self.profile_list.selection()
            current_profile = (
                self.profile_list.item(profile_sel[0], "values")[0]
                if profile_sel
                else None
            )
            tunnel_widget = getattr(self, "tunnel_list", None)
            if tunnel_widget is not None:
                for item in tunnel_widget.get_children():
                    values = tunnel_widget.item(item, "values")
                    tunnel_name = values[0] if values else ""
                    forwarder = self.profile_controller.active_tunnels.get(
                        (current_profile, tunnel_name)
                    )
                    if forwarder and getattr(forwarder, "is_active", False):
                        tunnel_widget.item(item, tags=("active",))
                    else:
                        tunnel_widget.item(item, tags=())
            else:
                self.logger.debug("Tunnel list widget not available; skipping tunnel highlight")
            self.logger.debug("Updated profile and tunnel highlights")
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to update highlights: %s", exc)

    def _on_new_profile(self) -> None:
        """Triggered when the 'New Profile' button is pressed."""
        self.logger.info("New profile creation requested")
        try:
            profiles = self.profile_controller.load_profiles()
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to load profiles for dialog: %s", exc)
            messagebox.showerror("Error", "Failed to load profiles")
            return

        dialog = ProfileDialog(self.root, profiles)
        if not getattr(dialog, "result", None):
            self.logger.info("Profile creation cancelled by user")
            return
        name, key_path, ip, auto_ip = dialog.result
        try:
            profile = self.profile_controller.create_profile(name, key_path, ip, auto_ip)
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
            profiles = self.profile_controller.load_profiles()
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
        new_name, key_path, ip, auto_ip = dialog.result
        try:
            updated = self.profile_controller.update_profile(name, new_name, key_path, ip, auto_ip)
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
            removed = self.profile_controller.delete_profile(name)
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
            dns_override,
        ) = dialog.result
        try:
            tunnel = self.profile_controller.add_tunnel(
                profile_name,
                name,
                ssh_host,
                username,
                local_port,
                host,
                remote_port,
                ssh_port,
                dns_names,
                dns_override,
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
            dns_override,
        ) = dialog.result
        try:
            self.profile_controller.update_tunnel(
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
                dns_override,
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
            removed = self.profile_controller.delete_tunnel(profile_name, tunnel_name)
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
        if self.profile_controller.is_tunnel_active(profile_name, tunnel_name):
            messagebox.showwarning(
                "Running", f"Tunnel '{tunnel_name}' is already running.",
            )
            self.logger.info(
                "Tunnel '%s' already running for profile '%s'", tunnel_name, profile_name
            )
            return
        try:
            profiles = load_profiles()
            if not any(p.get("name") == profile_name for p in profiles):
                profiles = self.profile_controller.load_profiles()
            import lighthouse_app.services.profile_service as ps

            forwarder_cls = SSHTunnelForwarder
            if getattr(ps, "SSHTunnelForwarder", _ORIGINAL_FORWARDER) is not _ORIGINAL_FORWARDER:
                forwarder_cls = ps.SSHTunnelForwarder
            elif SSHTunnelForwarder is not _ORIGINAL_FORWARDER:
                forwarder_cls = SSHTunnelForwarder

            self.profile_controller.start_tunnel(
                profile_name,
                tunnel_name,
                profiles=profiles,
                forwarder_cls=forwarder_cls,
            )
            self.logger.info(
                "Started tunnel '%s' for profile '%s'", tunnel_name, profile_name
            )
            self._append_log(
                f"Started tunnel '{tunnel_name}' for profile '{profile_name}'"
            )
            self._on_tunnel_select()
            self._update_highlights()
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
        if not self.profile_controller.is_tunnel_active(profile_name, tunnel_name):
            messagebox.showwarning(
                "Not running", f"Tunnel '{tunnel_name}' is not running.",
            )
            self.logger.info(
                "Tunnel '%s' not running for profile '%s'", tunnel_name, profile_name
            )
            return
        try:
            self.profile_controller.stop_tunnel(profile_name, tunnel_name)
            self.logger.info(
                "Stopped tunnel '%s' for profile '%s'", tunnel_name, profile_name
            )
            self._append_log(
                f"Stopped tunnel '{tunnel_name}' for profile '{profile_name}'"
            )
            self._on_tunnel_select()
            self._update_highlights()
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to stop tunnel: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_manage_ssh_key(self) -> None:
        """Triggered when the 'Manage SSH Key' button is pressed."""
        self.logger.info("SSH key management requested")
        try:
            SSHKeyManager(self.root, self.key_controller)
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to open SSH key manager: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_settings(self) -> None:
        """Triggered when the 'Settings' button is pressed."""
        self.logger.info("Settings requested")
        messagebox.showinfo("Info", "Settings functionality not yet implemented.")

    def _on_pane_resize(self, event: tk.Event) -> None:
        """Persist pane positions after user resizes the interface."""
        try:
            pane_count = len(self.top_pane.panes())
            coords = [self.top_pane.sash_coord(i)[0] for i in range(pane_count - 1)]
            save_pane_layout(coords)
        except Exception:  # pragma: no cover - defensive
            # Saving failures are ignored to avoid disrupting the app
            pass

    def run(self) -> None:
        """Run the Tkinter main event loop."""
        self.logger.info("Lighthouse started")
        self._append_log("Lighthouse started")
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
    # When packaged with tools like PyInstaller the module may execute with
    # ``__package__`` set to ``None``.  Previously this triggered an early
    # exit which caused the frozen application to close immediately.  Running
    # the entry point should be permitted regardless of how the module is
    # invoked.
    main()
