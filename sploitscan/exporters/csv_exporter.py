from __future__ import annotations

import csv
from typing import Any, Dict, List

from ..utils import generate_filename


def export_to_csv(all_results: List[Dict[str, Any]], cve_ids: List[str]) -> str:
    """
    Export the results to a CSV file.

    Behavior mirrors legacy exporter:
    - Fieldnames are derived from the first item's keys plus "Risk Assessment".
    - Rows are written as-is; nested structures will be stringified by csv module.
    """
    if not all_results:
        filename = generate_filename(cve_ids, "csv")
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["CVE Data", "EPSS Data", "CISA Data", "Nuclei Data", "GitHub Data",
                             "VulnCheck Data", "ExploitDB Data", "PacketStorm Data", "HackerOne Data",
                             "Priority", "Risk Assessment"])
        return filename

    filename = generate_filename(cve_ids, "csv")
    keys = list(all_results[0].keys())
    if "Risk Assessment" not in keys:
        keys = keys + ["Risk Assessment"]

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for item in all_results:
            # ensure key exists for writer
            if "Risk Assessment" not in item:
                item["Risk Assessment"] = item.get("Risk Assessment", "N/A")
            writer.writerow(item)
    return filename
