"""
CISA KEV fetcher utilities.

- Fetch the full CISA KEV JSON feed
- Annotate each vulnerability with derived fields used by UI
- Provide helper to extract a single CVE's relevant entry
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from ..constants import CISA_URL
from .common import fetch_json


def fetch_cisa_data() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Fetch the CISA Known Exploited Vulnerabilities JSON.
    On success, annotates each entry with:
      - cisa_status: "Yes"
      - ransomware_use: original knownRansomwareCampaignUse or "Unknown"

    Returns (json, None) or (None, error).
    """
    data, err = fetch_json(CISA_URL)
    if err:
        return None, err
    if not isinstance(data, dict):
        return None, "❌ Unexpected data format from CISA"

    vulns = data.get("vulnerabilities", [])
    if isinstance(vulns, list):
        for v in vulns:
            if isinstance(v, dict):
                v["cisa_status"] = "Yes"
                v["ransomware_use"] = v.get("knownRansomwareCampaignUse", "Unknown")
    return data, None


def extract_cve_entry(cve_id: str, cisa_data: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return the vulnerability entry for the given CVE ID from the CISA feed (if present)."""
    if not cisa_data or "vulnerabilities" not in cisa_data:
        return None
    for v in cisa_data.get("vulnerabilities", []):
        if isinstance(v, dict) and v.get("cveID") == cve_id:
            return v
    return None
