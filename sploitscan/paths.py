"""
Path utilities for SploitScan.

- Computes locations for local CVE repository and subdirectories
- Honors configured local_database_dir when provided
"""

from __future__ import annotations

import os
from typing import Dict, Optional

def get_cve_repo_dir(config: Optional[Dict] = None) -> str:
    """
    Return the base directory for the local cvelistV5 repository.
    If config provides "local_database_dir", use it; otherwise default to ~/.sploitscan
    """
    base_dir = None
    if config:
        base_dir = config.get("local_database_dir")
    if not base_dir:
        base_dir = os.path.expanduser("~/.sploitscan")
    return os.path.join(base_dir, "cvelistV5")


def get_cve_local_dir(config: Optional[Dict] = None) -> str:
    """Return the path to the local cvelistV5/cves directory."""
    return os.path.join(get_cve_repo_dir(config), "cves")
