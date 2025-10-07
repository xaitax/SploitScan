"""
HackerOne CVE details fetcher via GraphQL.

Returns basic rank, reports_submitted_count, and severity distribution for a CVE.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import requests

from ..constants import HACKERONE_URL


_QUERY = """
query CveDiscoveryDetailedViewCveEntry($cve_id: String!) {
  cve_entry(cve_id: $cve_id) {
    rank
    reports_submitted_count
    severity_count_unknown
    severity_count_none
    severity_count_low
    severity_count_medium
    severity_count_high
    severity_count_critical
    __typename
  }
}
"""


def fetch_hackerone_cve_details(cve_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Perform a POST to HackerOne GraphQL API for the given CVE.

    Returns:
      (json, None) on success with "data" -or-
      (None, error_message) on failure
    """
    headers = {"content-type": "application/json"}
    payload = {
        "operationName": "CveDiscoveryDetailedViewCveEntry",
        "variables": {"cve_id": cve_id},
        "query": _QUERY,
    }

    try:
        resp = requests.post(HACKERONE_URL, headers=headers, json=payload, timeout=30)
    except requests.RequestException as e:
        return None, f"❌ Error fetching data from HackerOne: {e}"

    if resp.status_code != 200:
        return None, f"❌ Error fetching data from HackerOne: {resp.status_code}: {resp.text}"

    try:
        data = resp.json()
    except ValueError as e:
        return None, f"❌ Error parsing JSON data from HackerOne: {e}"

    if "data" in data and "cve_entry" in data["data"]:
        return data, None
    return None, "❌ No HackerOne data found for this CVE."
