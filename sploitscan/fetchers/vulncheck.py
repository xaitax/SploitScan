"""
VulnCheck fetcher utilities.

Requires an API key in config under "vulncheck_api_key".
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from ..constants import VULNCHECK_API_URL
from ..config import load_config
from .common import fetch


def fetch_vulncheck_data(
    cve_id: str,
    *,
    config: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Fetch VulnCheck data for a CVE.

    Returns (json, None) on success, (None, error) on failure.
    """
    cfg = config or load_config()
    api_key = cfg.get("vulncheck_api_key")
    if not api_key:
        return None, "No VulnCheck API key is configured."

    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {api_key}",
    }

    resp, err = fetch(VULNCHECK_API_URL, params={"cve": cve_id}, headers=headers)
    if err:
        return None, err

    try:
        return resp.json(), None  # type: ignore[return-value]
    except ValueError as e:
        return None, f"Error parsing JSON data from VulnCheck: {e}"