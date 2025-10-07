"""
Utility helpers for SploitScan.
"""

from __future__ import annotations

import datetime
import os
import re
from typing import Iterable, List


def parse_iso_date(date_string: str, date_format: str = "%Y-%m-%d") -> str:
    """
    Parse an ISO date string (optionally ending with 'Z') and format it.
    Returns the original string if parsing fails or input is falsy.
    """
    if not date_string:
        return ""
    try:
        return datetime.datetime.fromisoformat(date_string.rstrip("Z")).strftime(date_format)
    except ValueError:
        return date_string


def datetimeformat(value: str, format: str = "%Y-%m-%d") -> str:
    """Jinja2 filter wrapper to format ISO dates."""
    return parse_iso_date(value, format)


_CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}$")


def is_valid_cve_id(cve_id: str) -> bool:
    """Validate CVE ID format (CVE-YYYY-NNNN+)."""
    return bool(_CVE_REGEX.match(cve_id))


def generate_filename(cve_ids: Iterable[str], extension: str) -> str:
    """
    Generate a timestamped filename like:
    20250101T123456Z_CVE-2024-1709_CVE-2024-21413_and_more_export.html
    """
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    ids: List[str] = list(cve_ids)
    cve_part = "_".join(ids[:3]) + ("_and_more" if len(ids) > 3 else "")
    cve_part = cve_part or "report"
    return f"{ts}_{cve_part}_export.{extension.lower()}"
