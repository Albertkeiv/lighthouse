import configparser
import logging
from pathlib import Path
from typing import List, Union
import tkinter as tk
from tkinter import messagebox, simpledialog

from .profiles import create_profile, load_profiles, delete_profile

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


class LighthouseApp:
    """Graphical interface for managing profiles and tunnels.

    This class constructs the Tkinter widgets according to the desired layout
    and logs all user actions for easier debugging.
    """

    def __init__(self, root: tk.Tk, cfg: configparser.ConfigParser) -> None:
        self.root = root
        self.cfg = cfg
        self.logger = logging.getLogger(__name__)
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
        # Configure grid for the main window
        self.root.columnconfigure(0, weight=1)
        self.root.columnconfigure(1, weight=1)
        self.root.columnconfigure(2, weight=3)
        # Top row holds the main content and expands to fill extra space.
        self.root.rowconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=0)

        # Paned window to allow user resizing between sections
        sash_width = sash_width_from_config(self.cfg)
        self.top_pane = tk.PanedWindow(
            self.root, orient=tk.HORIZONTAL, sashwidth=sash_width
        )
        self.top_pane.grid(row=0, column=0, columnspan=3, sticky="nsew")
        self.top_pane.bind("<ButtonRelease-1>", self._on_pane_resize)

        # Profiles list
        profile_frame = tk.Frame(self.top_pane, bd=2, relief=tk.GROOVE)
        self.top_pane.add(profile_frame, minsize=100)
        self.profile_list = tk.Listbox(profile_frame)
        self.profile_list.pack(fill=tk.BOTH, expand=True)
        self.profile_list.bind("<<ListboxSelect>>", self._on_profile_select)
        delete_btn = tk.Button(
            profile_frame, text="Delete Profile", command=self._on_delete_profile
        )
        delete_btn.pack(fill="x")
        self._load_profiles_into_list()

        # Tunnels list
        tunnel_frame = tk.Frame(self.top_pane, bd=2, relief=tk.GROOVE)
        self.top_pane.add(tunnel_frame, minsize=100)
        self.tunnel_list = tk.Listbox(tunnel_frame)
        self.tunnel_list.pack(fill=tk.BOTH, expand=True)
        self.tunnel_list.bind("<<ListboxSelect>>", self._on_tunnel_select)

        # Info and log area
        info_frame = tk.Frame(self.top_pane)
        self.top_pane.add(info_frame, minsize=200)
        info_frame.rowconfigure(0, weight=3)
        info_frame.rowconfigure(1, weight=1)

        # Restore pane layout after all panes have been added.
        # Calling this earlier results in errors because sashes do not yet exist.
        self.root.after(0, self._restore_pane_layout)

        self.status_text = tk.Text(info_frame, height=10)
        self.status_text.grid(row=0, column=0, sticky="nsew")
        self.status_text.insert(tk.END, "<TUNNEL_INFO_AND_STATUS>")

        self.log_text = tk.Text(info_frame, height=8)
        self.log_text.grid(row=1, column=0, sticky="nsew")
        self.log_text.insert(tk.END, "<LOG>")

        # Bottom buttons
        new_profile_btn = tk.Button(
            self.root, text="New Profile", command=self._on_new_profile
        )
        new_profile_btn.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

        new_tunnel_btn = tk.Button(
            self.root, text="New Tunnel", command=self._on_new_tunnel
        )
        new_tunnel_btn.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        settings_btn = tk.Button(
            self.root, text="Program Settings", command=self._on_settings
        )
        settings_btn.grid(row=1, column=2, sticky="ew", padx=5, pady=5)

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
        selection = event.widget.curselection()
        if selection:
            index = selection[0]
            value = event.widget.get(index)
            self.logger.info("Profile selected: %s", value)

    def _on_tunnel_select(self, event: tk.Event) -> None:
        """Handle tunnel selection event."""
        selection = event.widget.curselection()
        if selection:
            index = selection[0]
            value = event.widget.get(index)
            self.logger.info("Tunnel selected: %s", value)

    def _load_profiles_into_list(self) -> None:
        """Populate the profiles listbox from stored profiles."""
        try:
            profiles = load_profiles()
            for profile in profiles:
                display = f"{profile['name']} ({profile['ip']})"
                self.profile_list.insert(tk.END, display)
        except Exception as exc:  # pragma: no cover - defensive
            self.logger.exception("Failed to load profiles: %s", exc)

    def _on_new_profile(self) -> None:
        """Triggered when the 'New Profile' button is pressed."""
        self.logger.info("New profile creation requested")
        name = simpledialog.askstring("Profile Name", "Enter profile name:")
        if not name:
            self.logger.info("Profile creation cancelled: no name provided")
            return
        key_path = simpledialog.askstring("SSH Key Path", "Enter path to SSH key:")
        if not key_path:
            self.logger.info("Profile creation cancelled: no SSH key path provided")
            return
        use_auto = messagebox.askyesno(
            "IP Assignment", "Assign IP address automatically?"
        )
        if use_auto:
            ip = None
            self.logger.info("User opted for automatic IP assignment")
        else:
            ip = simpledialog.askstring("IP Address", "Enter IP address:")
            if not ip:
                self.logger.info(
                    "Profile creation cancelled: no IP address provided"
                )
                return
            self.logger.info("User provided manual IP %s", ip)
        try:
            profile = create_profile(name, key_path, ip)
            display = f"{profile['name']} ({profile['ip']})"
            self.profile_list.insert(tk.END, display)
            messagebox.showinfo("Success", f"Profile '{profile['name']}' created")
        except Exception as exc:
            self.logger.exception("Failed to create profile: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_delete_profile(self) -> None:
        """Triggered when the 'Delete Profile' button is pressed."""
        self.logger.info("Profile deletion requested")
        selection = self.profile_list.curselection()
        if not selection:
            messagebox.showwarning("No selection", "Please select a profile to delete.")
            self.logger.info("Profile deletion cancelled: no profile selected")
            return
        index = selection[0]
        value = self.profile_list.get(index)
        name = value.split(" (", 1)[0]
        if not messagebox.askyesno("Confirm", f"Delete profile '{name}'?"):
            self.logger.info("Profile deletion cancelled by user")
            return
        try:
            removed = delete_profile(name)
            if removed:
                self.profile_list.delete(index)
                messagebox.showinfo("Deleted", f"Profile '{name}' deleted")
                self.logger.info("Profile '%s' deleted", name)
            else:
                messagebox.showwarning("Not found", f"Profile '{name}' not found")
                self.logger.warning("Profile '%s' not found during deletion", name)
        except Exception as exc:
            self.logger.exception("Failed to delete profile: %s", exc)
            messagebox.showerror("Error", str(exc))

    def _on_new_tunnel(self) -> None:
        """Triggered when the 'New Tunnel' button is pressed."""
        self.logger.info("New tunnel creation requested")
        messagebox.showinfo("Info", "New Tunnel functionality not yet implemented.")

    def _on_settings(self) -> None:
        """Triggered when the 'Program Settings' button is pressed."""
        self.logger.info("Program settings requested")
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
