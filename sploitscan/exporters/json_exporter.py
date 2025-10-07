from __future__ import annotations

import json
from typing import Any, Dict, List

from ..utils import generate_filename


def export_to_json(all_results: List[Dict[str, Any]], cve_ids: List[str]) -> str:
    """Write results to a JSON file and return the filename."""
    filename = generate_filename(cve_ids, "json")
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=4)
    return filename
