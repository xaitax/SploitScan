"""
GitHub PoC index fetcher.

Uses the nomi-sec PoC-in-GitHub API index to retrieve PoCs for a given CVE.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from ..constants import GITHUB_API_URL
from .common import fetch_json


def fetch_github_pocs(cve_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Fetch GitHub PoCs for the given CVE ID.

    API: https://poc-in-github.motikan2010.net/api/v1/?cve_id=CVE-XXXX-YYYY
    Returns (json, None) or (None, error)
    The JSON typically includes a "pocs" list with entries containing html_url and created_at.
    """
    return fetch_json(GITHUB_API_URL, params={"cve_id": cve_id})
