"""Tests for saving and loading pane layout information."""

import configparser
from pathlib import Path
from typing import List

# Ensure module import
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lighthouse_app import ui


def _expected_coords() -> List[int]:
    """Read expected coordinates from sample config file."""
    cfg = configparser.ConfigParser()
    sample = Path(__file__).with_name("pane_layout_sample.ini")
    cfg.read(sample)
    return [
        cfg.getint("panes", key)
        for key in sorted(cfg["panes"], key=lambda k: int(k.split("_")[-1]))
    ]


def test_load_pane_layout_from_file():
    sample = Path(__file__).with_name("pane_layout_sample.ini")
    expected = _expected_coords()
    assert ui.load_pane_layout(sample) == expected


def test_save_pane_layout_creates_file(tmp_path):
    coords = _expected_coords()
    target = tmp_path / "pane_layout.ini"
    ui.save_pane_layout(coords, target)
    assert target.exists()
    assert ui.load_pane_layout(target) == coords

