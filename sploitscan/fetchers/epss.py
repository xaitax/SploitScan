"""
EPSS fetcher utilities.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from ..constants import EPSS_API_URL
from .common import fetch_json


def fetch_epss_score(cve_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Fetch EPSS score for a given CVE ID.
    Returns (json, None) or (None, error).
    """
    url = EPSS_API_URL.format(cve_id=cve_id)
    return fetch_json(url)
