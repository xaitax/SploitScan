"""
Nuclei templates fetcher utilities.

Strategy:
1) Try the cves.json NDJSON index (fast path).
2) If not found, try direct path on main:
     http/cves/{year}/{CVE}.yaml
3) If still not found, use GitHub code search API to locate the file path and
   construct a commit-pinned raw URL.

Returns a dict similar to the NDJSON entry with at least:
  - ID
  - file_path
Optionally includes:
  - raw_url (commit-pinned raw URL)
"""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple

import requests  # type: ignore[import-untyped]

from ..constants import NUCLEI_URL
from .common import iter_json_lines


RAW_BASE = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates"


def _url_exists(url: str, timeout: int = 15) -> bool:
    try:
        resp = requests.get(url, timeout=timeout, stream=True)
        return resp.status_code < 400
    except requests.RequestException:
        return False


def _guess_main_path(cve_id: str) -> Optional[str]:
    try:
        year = cve_id.split("-")[1]
    except Exception:
        return None
    return f"http/cves/{year}/{cve_id}.yaml"


def _search_github_path(cve_id: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Use GitHub code search to locate the nuclei template file path.

    Returns:
      (path, sha) or (None, None)
    """
    try:
        url = "https://api.github.com/search/code"
        params = {"q": f"repo:projectdiscovery/nuclei-templates+filename:{cve_id}.yaml"}
        resp = requests.get(url, params=params, timeout=30)
        if resp.status_code != 200:
            return None, None
        data = resp.json()
        items = data.get("items", [])
        if not items:
            return None, None
        item = items[0]
        path = item.get("path")
        sha = item.get("sha")
        if path and sha:
            return path, sha
        return None, None
    except Exception:
        return None, None


def fetch_nuclei_data(cve_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Find the Nuclei template metadata for a given CVE ID.

    Returns:
      (template_dict, None) if found
      (None, None) if not found
      (None, error_message) on error
    """
    # 1) Try NDJSON index
    lines, err = iter_json_lines(NUCLEI_URL)
    if err:
        # Not fatal — continue with fallbacks
        lines = None
    if lines is not None:
        for line in lines:
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("ID") == cve_id:
                return obj, None

    # 2) Try direct main path guess
    guess_path = _guess_main_path(cve_id)
    if guess_path:
        main_raw = f"{RAW_BASE}/main/{guess_path}"
        if _url_exists(main_raw):
            return {"ID": cve_id, "file_path": guess_path}, None

    # 3) GitHub code search to find a commit-pinned path
    path, sha = _search_github_path(cve_id)
    if path and sha:
        raw_url = f"{RAW_BASE}/{sha}/{path}"
        # Return file_path for compatibility with consumers,
        # and include raw_url for consumers that prefer commit-pinned links.
        return {"ID": cve_id, "file_path": path, "raw_url": raw_url}, None

    # Not found
    return None, None
