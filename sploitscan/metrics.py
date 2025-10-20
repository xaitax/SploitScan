"""
Security metrics helpers (CVSS extraction, priority calculation).
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from .constants import CVSS_THRESHOLD, EPSS_THRESHOLD


def extract_cvss_info(cve_data: Optional[Dict[str, Any]]) -> Tuple[str, str, str]:
    """
    Extract (base_score, base_severity, vector_string) from cvelistV5 JSON.

    Order of preference:
      - cvssV4_0
      - cvssV3_1
      - cvssV3_0
      - cvssV3
      - ADP entries (same order)
    Returns ("N/A", "N/A", "N/A") if not found.
    """
    base_score, base_severity, vector = "N/A", "N/A", "N/A"
    if not cve_data or "containers" not in cve_data or "cna" not in cve_data["containers"]:
        return base_score, base_severity, vector

    cna = cve_data["containers"]["cna"]
    metrics = cna.get("metrics", [])
    for metric in metrics:
        cvss_data = (
            metric.get("cvssV4_0")
            or metric.get("cvssV3_1")
            or metric.get("cvssV3_0")
            or metric.get("cvssV3")
        )
        if cvss_data and cvss_data.get("baseScore"):
            base_score = cvss_data.get("baseScore", "N/A")
            base_severity = cvss_data.get("baseSeverity", "N/A")
            vector = cvss_data.get("vectorString", "N/A")
            return str(base_score), str(base_severity), str(vector)

    adp_entries = cve_data["containers"].get("adp", [])
    for adp_entry in adp_entries:
        for metric in adp_entry.get("metrics", []):
            cvss_data = (
                metric.get("cvssV4_0")
                or metric.get("cvssV3_1")
                or metric.get("cvssV3_0")
                or metric.get("cvssV3")
            )
            if cvss_data and cvss_data.get("baseScore"):
                base_score = cvss_data.get("baseScore", "N/A")
                base_severity = cvss_data.get("baseSeverity", "N/A")
                vector = cvss_data.get("vectorString", "N/A")
                return str(base_score), str(base_severity), str(vector)

    return str(base_score), str(base_severity), str(vector)


def calculate_priority(
    cve_id: str,
    cve_data: Optional[Dict[str, Any]],
    epss_data: Optional[Dict[str, Any]],
    github_data: Optional[Dict[str, Any]],
    cisa_data: Optional[Dict[str, Any]],
    vulncheck_data: Optional[Dict[str, Any]],
    exploitdb_data: Optional[list],
) -> Optional[str]:
    """
    Compute patching priority letter:
      - A+ if listed in CISA KEV or any public exploit observed
      - A if CVSS >= CVSS_THRESHOLD and EPSS >= EPSS_THRESHOLD
      - B if CVSS >= CVSS_THRESHOLD
      - C if EPSS >= EPSS_THRESHOLD
      - D otherwise when at least one signal exists
      - None if no signals are present
    """
    cvss_score = 0.0
    epss_score = 0.0

    try:
        base_score, _, _ = extract_cvss_info(cve_data)
        cvss_score = float(base_score)
    except (TypeError, ValueError):
        pass

    try:
        epss_score = float(epss_data["data"][0]["epss"]) if epss_data and "data" in epss_data else 0.0
    except (KeyError, IndexError, TypeError, ValueError):
        pass

    in_cisa_kev = False
    if cisa_data and isinstance(cisa_data, dict):
        vulns = cisa_data.get("vulnerabilities", [])
        in_cisa_kev = any(isinstance(v, dict) and v.get("cveID") == cve_id for v in vulns)

    has_public_exploits = False
    if github_data and isinstance(github_data, dict):
        has_public_exploits = bool(github_data.get("pocs"))
    if not has_public_exploits and vulncheck_data and isinstance(vulncheck_data, dict):
        has_public_exploits = bool(vulncheck_data.get("data"))
    if not has_public_exploits and exploitdb_data:
        has_public_exploits = bool(exploitdb_data)

    if not (cvss_score or epss_score or in_cisa_kev or has_public_exploits):
        return None

    if in_cisa_kev:
        base_grade = "A+"
    elif cvss_score >= CVSS_THRESHOLD and epss_score >= EPSS_THRESHOLD:
        base_grade = "A"
    elif cvss_score >= CVSS_THRESHOLD:
        base_grade = "B"
    elif epss_score >= EPSS_THRESHOLD:
        base_grade = "C"
    else:
        base_grade = "D"

    # Grade escalation if public exploit is known
    if has_public_exploits and base_grade != "A+":
        grade_order = ["D", "C", "B", "A", "A+"]
        current_index = grade_order.index(base_grade)
        new_index = min(current_index + 2, len(grade_order) - 1)
        return grade_order[new_index]

    return base_grade
