import logging
from pathlib import Path
from typing import List, Union


def add_hosts_block(
    profile_name: str,
    ip: str,
    dns_names: List[str],
    hosts_file: Union[str, Path],
    logger: logging.Logger,
) -> None:
    """Add managed block with DNS records to hosts file.

    Existing block for the profile is replaced. If ``dns_names`` is empty
    the function simply returns without touching the file.
    """
    if not dns_names:
        logger.info(
            "No DNS names for profile '%s'; skipping hosts update", profile_name
        )
        return
    path = Path(hosts_file)
    block_start = f"#### Managed by Lighthouse profile {profile_name} ####"
    block_end = f"#### End block Lighthouse profile {profile_name} ####"
    record_line = f"{ip} {' '.join(dns_names)}"
    try:
        # Remove existing block first
        remove_hosts_block(profile_name, path, logger)
        with path.open("a", encoding="utf-8") as handle:
            handle.write("\n".join([block_start, record_line, block_end, ""]))
        logger.info(
            "Appended hosts block for profile '%s' with names '%s'", profile_name, " ".join(dns_names)
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Failed to update hosts file %s: %s", path, exc)
        raise


def remove_hosts_block(
    profile_name: str,
    hosts_file: Union[str, Path],
    logger: logging.Logger,
) -> None:
    """Remove managed block for the given profile from hosts file."""
    path = Path(hosts_file)
    if not path.exists():
        logger.info("Hosts file %s not found; nothing to remove", path)
        return
    block_start = f"#### Managed by Lighthouse profile {profile_name} ####"
    block_end = f"#### End block Lighthouse profile {profile_name} ####"
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        new_lines = []
        skip = False
        for line in lines:
            if line.strip() == block_start:
                skip = True
                continue
            if skip and line.strip() == block_end:
                skip = False
                continue
            if not skip:
                new_lines.append(line)
        if new_lines:
            new_lines.append("")  # ensure newline at end
        path.write_text("\n".join(new_lines), encoding="utf-8")
        logger.info(
            "Removed hosts block for profile '%s' from %s", profile_name, path
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Failed to clean hosts file %s: %s", path, exc)
        raise
