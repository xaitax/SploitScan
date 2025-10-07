from __future__ import annotations

from typing import Any, Dict, Optional


def compile_cve_details(
    cve_id: str,
    cve_data: Dict[str, Any],
    epss_data: Optional[Dict[str, Any]],
    relevant_cisa_data: Optional[Dict[str, Any]],
    public_exploits: Dict[str, Any],
) -> str:
    published = cve_data.get("cveMetadata", {}).get("datePublished", "N/A") if cve_data else "N/A"
    description = (
        next(
            (
                desc.get("value", "")
                for desc in cve_data.get("containers", {}).get("cna", {}).get("descriptions", [])
                if desc.get("lang") == "en"
            ),
            "No description available",
        )
        .replace("\n\n", " ")
        .replace("  ", " ")
        if cve_data
        else "No description available"
    )

    # CVSS info (stringly typed here; caller may use metrics.extract_cvss_info elsewhere)
    base_score = "N/A"
    base_severity = "N/A"
    vector_string = "N/A"
    try:
        containers = cve_data.get("containers", {})
        cna = containers.get("cna", {})
        metrics = cna.get("metrics", [])
        if metrics:
            cvss = (
                metrics[0].get("cvssV4_0")
                or metrics[0].get("cvssV3_1")
                or metrics[0].get("cvssV3_0")
                or metrics[0].get("cvssV3")
            )
            if cvss:
                base_score = str(cvss.get("baseScore", "N/A"))
                base_severity = str(cvss.get("baseSeverity", "N/A"))
                vector_string = str(cvss.get("vectorString", "N/A"))
    except Exception:
        pass

    epss_score = (
        epss_data.get("data", [{}])[0].get("epss", "N/A")
        if epss_data and isinstance(epss_data, dict) and epss_data.get("data")
        else "N/A"
    )

    cisa_status = relevant_cisa_data.get("cisa_status", "N/A") if relevant_cisa_data else "N/A"
    ransomware_use = relevant_cisa_data.get("ransomware_use", "N/A") if relevant_cisa_data else "N/A"

    github_exploits = (
        "\n".join(
            [
                f"{poc.get('created_at', 'N/A')}: {poc.get('html_url', 'N/A')}"
                for poc in (public_exploits.get("github_data") or {}).get("pocs", [])
            ]
        )
        if public_exploits.get("github_data")
        else "N/A"
    )

    vulncheck_exploits = (
        "\n".join(
            [
                f"{xdb.get('date_added', 'N/A')}: "
                f"{(xdb.get('clone_ssh_url', '') or '').replace('git@github.com:', 'https://github.com/').replace('.git', '')}"
                for item in (public_exploits.get("vulncheck_data") or {}).get("data", [])
                for xdb in item.get("vulncheck_xdb", [])
            ]
        )
        if public_exploits.get("vulncheck_data")
        else "N/A"
    )

    packetstorm_url = (public_exploits.get("packetstorm_data") or {}).get("packetstorm_url", "N/A")
    nuclei_url = (
        f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/{(public_exploits.get('nuclei_data') or {}).get('file_path')}"
        if public_exploits.get("nuclei_data") and (public_exploits.get("nuclei_data") or {}).get("file_path")
        else "N/A"
    )

    references_list = (
        cve_data.get("containers", {}).get("cna", {}).get("references", [])
        if cve_data
        else []
    )
    references = "\n".join([ref.get("url", "") for ref in references_list]) if references_list else "N/A"

    return f"""
Published: {published}
Base Score: {base_score} ({base_severity})
Vector: {vector_string}
Description: {description}
EPSS Score: {epss_score}
CISA Status: {cisa_status}
Ransomware Use: {ransomware_use}
GitHub Exploits: {github_exploits}
VulnCheck Exploits: {vulncheck_exploits}
PacketStorm URL: {packetstorm_url}
Nuclei Template: {nuclei_url}
Further References: {references}
"""
