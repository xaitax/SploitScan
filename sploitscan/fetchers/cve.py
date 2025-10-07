"""
CVE data fetcher utilities.

- Build raw GitHub URL for CVE JSON in cvelistV5
- Fetch CVE JSON from GitHub
- Optionally load CVE JSON from local cloned database
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional, Tuple

from ..constants import CVE_GITHUB_URL
from ..paths import get_cve_local_dir
from .common import fetch_json


def _cve_path_parts(cve_id: str) -> Tuple[str, str]:
    """Return (year, thousand_group) for the CVE id."""
    parts = cve_id.split("-")
    if len(parts) < 3:
        raise ValueError(f"Invalid CVE ID format: {cve_id}")
    year = parts[1]
    try:
        cve_num = int(parts[2])
    except ValueError:
        raise ValueError(f"Invalid CVE numeric part: {cve_id}")
    thousand_group = f"{cve_num // 1000}xxx"
    return year, thousand_group


def build_github_cve_url(cve_id: str) -> str:
    """Construct the raw GitHub URL to the CVE JSON in cvelistV5."""
    year, thousand = _cve_path_parts(cve_id)
    return f"{CVE_GITHUB_URL}/{year}/{thousand}/{cve_id}.json"


def fetch_cve_from_github(cve_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Fetch CVE JSON from cvelistV5 raw on GitHub.
    Returns (json, None) or (None, error).
    """
    url = build_github_cve_url(cve_id)
    return fetch_json(url)


def load_cve_from_local(cve_id: str, *, config: Optional[Dict[str, Any]] = None) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Load CVE JSON from a locally cloned cvelistV5 repository if available.
    Returns (json, None) or (None, error).
    """
    year, thousand = _cve_path_parts(cve_id)
    base = get_cve_local_dir(config)
    cve_path = os.path.join(base, year, thousand, f"{cve_id}.json")
    if not os.path.exists(cve_path):
        return None, f"Local CVE file not found: {cve_path}"
    try:
        with open(cve_path, "r", encoding="utf-8") as f:
            return json.load(f), None
    except json.JSONDecodeError as e:
        return None, f"❌ Error parsing local CVE JSON {cve_path}: {e}"
    except Exception as e:
        return None, f"❌ Error reading local CVE JSON {cve_path}: {e}"
