from __future__ import annotations

import json
from typing import Iterable, List, Optional, Set

from .repo import grep_local_db
from .fetchers.cisa import fetch_cisa_data
from .fetchers.common import iter_json_lines
from .constants import NUCLEI_URL


def search_cve_by_keywords(keywords: Iterable[str]) -> List[str]:
    """
    Aggregate CVE IDs matching all keywords across:
    - Local cvelistV5 JSON database (if present)
    - CISA KEV JSON
    - Nuclei cves.json NDJSON index

    Matching is case-insensitive and requires all keywords to be present within the serialized record.
    """
    kws = [k.lower() for k in (list(keywords) if not isinstance(keywords, str) else [keywords])]
    results: Set[str] = set()

    # Local grep
    local_cve_ids = grep_local_db(kws)
    if local_cve_ids:
        results.update(local_cve_ids)

    # CISA feed
    cisa_data, cisa_err = fetch_cisa_data()
    if cisa_data and not cisa_err:
        for item in cisa_data.get("vulnerabilities", []):
            try:
                item_str = json.dumps(item).lower()
            except Exception:
                continue
            if all(kw in item_str for kw in kws):
                cve_id = item.get("cveID")
                if cve_id:
                    results.add(cve_id)

    # Nuclei NDJSON
    lines, nuclei_err = iter_json_lines(NUCLEI_URL)
    if lines and not nuclei_err:
        for line in lines:
            try:
                lower = line.lower()
            except Exception:
                continue
            if all(kw in lower for kw in kws):
                try:
                    obj = json.loads(line)
                    cve_id = obj.get("ID")
                    if cve_id:
                        results.add(cve_id)
                except Exception:
                    continue

    return sorted(results)
