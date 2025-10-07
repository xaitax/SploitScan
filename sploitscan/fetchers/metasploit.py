from __future__ import annotations

"""
Metasploit module discovery based on Rapid7's official modules_metadata_base.json.

Approach:
- Download modules_metadata_base.json from rapid7/metasploit-framework (raw GitHub).
- Use conditional requests (ETag/Last-Modified) to avoid re-downloading when unchanged.
- Build a CVE -> [ModuleInfo] index by matching CVE tokens only in the "references" field.
- Expose fetch_metasploit_modules_for_cve(cve_id) to retrieve verified modules for a CVE.

 """

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

# Raw metadata URL (about ~10MB). Using master to keep it up-to-date.
MSF_METADATA_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"

# Cache locations
CACHE_BASE_DIR = os.path.expanduser("~/.sploitscan/cache/metasploit")
CACHE_JSON_PATH = os.path.join(CACHE_BASE_DIR, "modules_metadata_base.json")
CACHE_META_PATH = os.path.join(CACHE_BASE_DIR, "modules_metadata_base.json.meta")

DEFAULT_TIMEOUT = 30

_CVE_INDEX: Optional[Dict[str, List[Dict[str, Any]]]] = None
_LAST_LOADED_ETAG: Optional[str] = None

_CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Mapping from MSF numeric rank to human-friendly label
_RANK_LABELS = {
    600: "Excellent",
    500: "Great",
    400: "Good",
    300: "Normal",
    200: "Average",
    100: "Low",
    0: "Manual",
}


def _ensure_cache_dir() -> None:
    os.makedirs(CACHE_BASE_DIR, exist_ok=True)


def _read_meta() -> Dict[str, Any]:
    try:
        with open(CACHE_META_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _write_meta(meta: Dict[str, Any]) -> None:
    try:
        with open(CACHE_META_PATH, "w", encoding="utf-8") as f:
            json.dump(meta, f)
    except Exception:
        # Non-fatal
        pass


def _load_cached_json() -> Optional[Dict[str, Any]]:
    try:
        if not os.path.exists(CACHE_JSON_PATH):
            return None
        with open(CACHE_JSON_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _save_json_to_cache(data: Dict[str, Any]) -> None:
    try:
        with open(CACHE_JSON_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f)
    except Exception:
        # Non-fatal
        pass


def _conditional_download() -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Download the metadata JSON with conditional headers (ETag / If-Modified-Since).
    Returns (json, error) where json can be None if not modified (fallback to cache).
    """
    _ensure_cache_dir()
    headers: Dict[str, str] = {"Accept": "application/json"}
    meta = _read_meta()
    etag = meta.get("etag")
    last_modified = meta.get("last_modified")

    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified

    try:
        resp = requests.get(MSF_METADATA_URL, headers=headers, timeout=DEFAULT_TIMEOUT)
        if resp.status_code == 304:
            # Not modified; use cache
            cached = _load_cached_json()
            if cached is None:
                # Unexpected: 304 but no cache; try full download
                resp = requests.get(MSF_METADATA_URL, timeout=DEFAULT_TIMEOUT)
                resp.raise_for_status()
                data = resp.json()
                _save_json_to_cache(data)
                # Update meta
                _write_meta(
                    {
                        "etag": resp.headers.get("ETag"),
                        "last_modified": resp.headers.get("Last-Modified"),
                        "fetched_at": int(time.time()),
                    }
                )
                return data, None
            return cached, None

        resp.raise_for_status()
        data = resp.json()
        _save_json_to_cache(data)
        _write_meta(
            {
                "etag": resp.headers.get("ETag"),
                "last_modified": resp.headers.get("Last-Modified"),
                "fetched_at": int(time.time()),
            }
        )
        return data, None
    except requests.exceptions.RequestException as e:
        # Network failed; use cache if available
        cached = _load_cached_json()
        if cached is not None:
            return cached, None
        return None, f"❌ Error fetching Metasploit metadata: {e}"
    except ValueError as e:
        return None, f"❌ Error parsing Metasploit metadata JSON: {e}"


def _rank_label(num: Any) -> str:
    try:
        n = int(num)
    except Exception:
        return "Unknown"
    return _RANK_LABELS.get(n, str(n))


def _build_index(metadata: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Build a dict mapping CVE -> list[ModuleInfo] from modules_metadata_base.json
    Only consider CVE IDs present in the 'references' array of each module entry.
    """
    index: Dict[str, List[Dict[str, Any]]] = {}
    for _key, mod in metadata.items():
        if not isinstance(mod, dict):
            continue

        refs = mod.get("references") or []
        if not isinstance(refs, list):
            continue

        # Extract CVE tokens from references only (high confidence)
        cves: List[str] = []
        for ref in refs:
            if not isinstance(ref, str):
                continue
            for match in _CVE_REGEX.findall(ref):
                # Normalize format to uppercase canonical
                cves.append(match.upper())

        if not cves:
            continue

        path = (mod.get("path") or "").lstrip("/")
        url = f"https://github.com/rapid7/metasploit-framework/blob/master/{path}" if path else None

        module_info = {
            "fullname": mod.get("fullname"),
            "type": mod.get("type"),
            "rank": mod.get("rank"),
            "rank_label": _rank_label(mod.get("rank")),
            "check": bool(mod.get("check", False)),
            "disclosure_date": mod.get("disclosure_date"),
            "url": url,
            "ref_name": mod.get("ref_name"),
        }

        for cve in set(cves):
            index.setdefault(cve, []).append(module_info)

    # Sort per-CVE by rank desc then name
    for cve, mods in index.items():
        mods.sort(key=lambda m: (int(m.get("rank") or 0), str(m.get("fullname") or "")), reverse=True)

    return index


def _ensure_index() -> Tuple[Optional[Dict[str, List[Dict[str, Any]]]], Optional[str]]:
    global _CVE_INDEX, _LAST_LOADED_ETAG

    if _CVE_INDEX is not None:
        return _CVE_INDEX, None

    data, err = _conditional_download()
    if err:
        return None, err
    if data is None:
        return None, "❌ Metasploit metadata is unavailable."

    _CVE_INDEX = _build_index(data)
    meta = _read_meta()
    _LAST_LOADED_ETAG = meta.get("etag")
    return _CVE_INDEX, None


def fetch_metasploit_modules_for_cve(cve_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Return Metasploit modules for a given CVE based solely on 'references' field matches.

    Output:
      {
        "modules": [
          {
            "fullname": str,
            "type": "exploit" | "auxiliary" | "post" | None,
            "rank": int | None,
            "rank_label": str,
            "check": bool,
            "disclosure_date": str | None,
            "url": str | None,
            "ref_name": str | None
          },
          ...
        ],
        "counts": {
          "exploit": int,
          "auxiliary": int,
          "post": int
        }
      }
    """
    idx, err = _ensure_index()
    if err:
        return None, err

    cve_key = cve_id.upper()
    mods = list(idx.get(cve_key, []))
    counts = {"exploit": 0, "auxiliary": 0, "post": 0}
    for m in mods:
        t = (m.get("type") or "").lower()
        if t in counts:
            counts[t] += 1

    return {"modules": mods, "counts": counts}, None
