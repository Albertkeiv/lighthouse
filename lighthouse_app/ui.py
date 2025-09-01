import logging
import tkinter as tk
from tkinter import messagebox
import configparser


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

    def _on_new_profile(self) -> None:
        """Triggered when the 'New Profile' button is pressed."""
        self.logger.info("New profile creation requested")
        messagebox.showinfo("Info", "New Profile functionality not yet implemented.")

    def _on_new_tunnel(self) -> None:
        """Triggered when the 'New Tunnel' button is pressed."""
        self.logger.info("New tunnel creation requested")
        messagebox.showinfo("Info", "New Tunnel functionality not yet implemented.")

    def _on_settings(self) -> None:
        """Triggered when the 'Program Settings' button is pressed."""
        self.logger.info("Program settings requested")
        messagebox.showinfo("Info", "Settings functionality not yet implemented.")

    def _on_pane_resize(self, event: tk.Event) -> None:
        """Log pane positions after user resizes the interface."""
        try:
            pane_count = len(self.top_pane.panes())
            coords = [
                self.top_pane.sash_coord(i) for i in range(pane_count - 1)
            ]
            self.logger.info("Pane resized; sash coordinates: %s", coords)
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
