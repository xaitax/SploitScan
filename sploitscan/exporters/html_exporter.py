from __future__ import annotations

import os
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader

from ..utils import datetimeformat, generate_filename
from ..metrics import extract_cvss_info


def _handle_cvss(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    for result in results:
        # GitHub PoCs
        github_pocs = 0
        gd = result.get("GitHub Data") or {}
        if isinstance(gd, dict):
            pocs = gd.get("pocs") or []
            if isinstance(pocs, list):
                github_pocs = len(pocs)
        else:
            pocs = []

        # VulnCheck XDBs
        vulncheck_count = 0
        vd = result.get("VulnCheck Data") or {}
        if isinstance(vd, dict):
            vc_items = vd.get("data") or []
            if isinstance(vc_items, list):
                for item in vc_items:
                    if isinstance(item, dict):
                        xdb = item.get("vulncheck_xdb") or []
                        if isinstance(xdb, list):
                            vulncheck_count += len(xdb)

        # Exploit-DB entries
        edb_count = 0
        edb = result.get("ExploitDB Data") or []
        if isinstance(edb, list):
            edb_count = len(edb)

        # Nuclei presence (count as 1 if present)
        nuclei_count = 0
        nd = result.get("Nuclei Data")
        if isinstance(nd, dict) and (nd.get("file_path") or nd.get("raw_url")):
            nuclei_count = 1

        # Metasploit modules (count all modules discovered for this CVE)
        metasploit_count = 0
        msf = result.get("Metasploit Data") or {}
        if isinstance(msf, dict):
            mods = msf.get("modules") or []
            if isinstance(mods, list):
                metasploit_count = len(mods)

        # Public Exploits Total
        result["Public Exploits Total"] = github_pocs + vulncheck_count + edb_count + nuclei_count + metasploit_count

        # Sort GitHub PoCs (by created_at desc) if present
        if isinstance(gd, dict) and isinstance(pocs, list) and pocs:
            gd["pocs"] = sorted(
                [x for x in pocs if isinstance(x, dict)],
                key=lambda x: x.get("created_at", ""),
                reverse=True,
            )
            result["GitHub Data"] = gd

        # Sort VulnCheck XDBs (by date_added desc)
        if isinstance(vd, dict):
            vc_items = vd.get("data") or []
            if isinstance(vc_items, list):
                for item in vc_items:
                    if isinstance(item, dict) and isinstance(item.get("vulncheck_xdb"), list):
                        item["vulncheck_xdb"] = sorted(
                            [x for x in item["vulncheck_xdb"] if isinstance(x, dict)],
                            key=lambda x: x.get("date_added", ""),
                            reverse=True,
                        )
                vd["data"] = vc_items
                result["VulnCheck Data"] = vd

        # Sort Exploit-DB entries (by date desc)
        if isinstance(edb, list) and edb:
            result["ExploitDB Data"] = sorted(
                [x for x in edb if isinstance(x, dict)],
                key=lambda x: x.get("date", ""),
                reverse=True,
            )

        # Normalize EPSS to float
        epss = result.get("EPSS Data")
        if isinstance(epss, dict):
            data_list = epss.get("data")
            if isinstance(data_list, list) and data_list:
                try:
                    epss_value = float(data_list[0].get("epss", 0))
                except (ValueError, TypeError):
                    epss_value = 0.0
                data_list[0]["epss"] = epss_value
                epss["data"] = data_list
                result["EPSS Data"] = epss

        # Normalize CVSS for HTML template convenience
        if (
            "CVE Data" in result
            and isinstance(result["CVE Data"], dict)
            and result["CVE Data"]
            and "containers" in result["CVE Data"]
        ):
            base_score, base_severity, vector_string = extract_cvss_info(result["CVE Data"])
            try:
                base_score_float = float(base_score)
            except (ValueError, TypeError):
                base_score_float = 0.0
            result["CVE Data"]["cvss_info"] = {
                "baseScore": base_score_float,
                "baseSeverity": base_severity,
                "vectorString": vector_string,
            }
    return results


def export_to_html(all_results: List[Dict[str, Any]], cve_ids: List[str]) -> str:
    """
    Render HTML report using the bundled Jinja2 template with the original paths fallback.
    Returns the output filename.
    """
    base_path = os.path.dirname(os.path.abspath(__file__))
    package_root = os.path.abspath(os.path.join(base_path, os.pardir))
    template_paths = [
        os.path.join(package_root, "templates"),
        os.path.expanduser("~/.sploitscan/templates"),
        os.path.expanduser("~/.config/sploitscan/templates"),
        "/etc/sploitscan/templates",
    ]

    env: Environment
    for path in template_paths:
        if os.path.exists(os.path.join(path, "report_template.html")):
            env = Environment(loader=FileSystemLoader(path))
            break
    else:
        raise FileNotFoundError("HTML template 'report_template.html' not found in any checked locations.")

    env.filters["datetimeformat"] = datetimeformat
    tmpl = env.get_template("report_template.html")
    filename = generate_filename(cve_ids, "html")
    output = tmpl.render(cve_data=_handle_cvss(all_results))

    with open(filename, "w", encoding="utf-8") as f:
        f.write(output)
    return filename
