#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import argparse
from typing import Any, Dict, List, Optional

from .constants import VERSION, BLUE, GREEN, YELLOW, ENDC
from .config import load_config
from .paths import get_cve_local_dir
from .display import (
    display_banner,
    print_cve_header,
    display_cve_data,
    display_epss_score,
    display_cisa_status,
    display_public_exploits,
    display_hackerone_data,
    display_cve_references,
    display_priority_rating,
    display_ai_risk_assessment,
)
from .fetchers.cve import fetch_cve_from_github, load_cve_from_local
from .fetchers.epss import fetch_epss_score
from .fetchers.cisa import fetch_cisa_data, extract_cve_entry
from .fetchers.nuclei import fetch_nuclei_data
from .fetchers.vulncheck import fetch_vulncheck_data
from .fetchers.exploitdb import fetch_exploitdb_data
from .fetchers.github_poc import fetch_github_pocs
from .fetchers.hackerone import fetch_hackerone_cve_details
from .fetchers.metasploit import fetch_metasploit_modules_for_cve
from .metrics import calculate_priority
from .compose import compile_cve_details
from .ai import get_risk_assessment
from .repo import clone_cvelistV5_repo
from .search import search_cve_by_keywords
from .importers import import_vulnerability_data
from .exporters.html_exporter import export_to_html
from .exporters.json_exporter import export_to_json
from .exporters.csv_exporter import export_to_csv


def _configure_console_encoding() -> None:
    """
    Ensure stdout/stderr can emit UTF-8 on Windows consoles to avoid UnicodeEncodeError.
    Falls back silently if reconfigure is unavailable.
    """
    try:
        import sys
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _ensure_cve_loaded(cve_id: str, *, fast_mode: bool, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Load CVE JSON either from local DB (fast path) or from GitHub.
    """
    cve_data: Optional[Dict[str, Any]] = None
    if fast_mode:
        cve_data, _ = load_cve_from_local(cve_id, config=config)
        if cve_data:
            return cve_data
    # Fallback: fetch from GitHub
    cve_data, _ = fetch_cve_from_github(cve_id)
    return cve_data


def _public_exploits_bundle(cve_id: str, *, config: Dict[str, Any], cve_data: Dict[str, Any]) -> Dict[str, Any]:
    github_data, _ = fetch_github_pocs(cve_id)

    # Fallback: if PoC-in-GitHub API returns nothing, derive GitHub entries from CVE references
    if not (github_data and isinstance(github_data, dict) and github_data.get("pocs")):
        try:
            refs = (cve_data or {}).get("containers", {}).get("cna", {}).get("references", [])
            fallback: list[dict] = []
            for ref in refs or []:
                url = (ref or {}).get("url", "")
                if "github.com/" in url:
                    fallback.append({"html_url": url, "created_at": "N/A"})
            if fallback:
                github_data = {"pocs": fallback}
        except Exception:
            # best-effort only
            pass

    vulncheck_data, vulncheck_error = fetch_vulncheck_data(cve_id, config=config)
    exploitdb_data, _ = fetch_exploitdb_data(cve_id)
    nuclei_data, _ = fetch_nuclei_data(cve_id)
    metasploit_data, _ = fetch_metasploit_modules_for_cve(cve_id)

    display_public_exploits(
        github_data=github_data,
        vulncheck_data=vulncheck_data if isinstance(vulncheck_data, dict) else {},
        exploitdb_data=exploitdb_data,
        nuclei_data=nuclei_data,
        metasploit_data=metasploit_data,
        vulncheck_error=vulncheck_error,
    )

    return {
        "github_data": github_data,
        "vulncheck_data": vulncheck_data if isinstance(vulncheck_data, dict) else {},
        "exploitdb_data": exploitdb_data,
        "packetstorm_data": {},
        "nuclei_data": nuclei_data,
        "metasploit_data": metasploit_data,
        "vulncheck_error": vulncheck_error,
    }


def _selected(methods: Optional[str]) -> set[str]:
    default_methods = {"cisa", "epss", "hackerone", "ai", "prio", "references"}
    if not methods:
        return default_methods
    return {m.strip().lower() for m in methods.split(",") if m.strip()}


def main(
    cve_ids: List[str],
    *,
    export_format: Optional[str] = None,
    import_file: Optional[str] = None,
    import_type: Optional[str] = None,
    ai_provider: Optional[str] = None,
    config_path: Optional[str] = None,
    methods: Optional[str] = None,
    debug: bool = False,
    fast_mode: bool = False,
) -> None:
    """
    Orchestrate SploitScan workflow for one or more CVE IDs.
    """
    config = load_config(config_path=config_path, debug=debug)

    all_results: List[Dict[str, Any]] = []
    selected = _selected(methods)

    # Normalize export format
    if export_format:
        export_format = export_format.lower()

    # Optional import
    if import_file:
        imported_ids = import_vulnerability_data(import_file, import_type)
        if not imported_ids:
            print("❌ No valid CVE IDs found in the provided file.")
            return
        cve_ids = imported_ids

    if not cve_ids:
        print("❌ No CVE IDs provided. Please provide CVE IDs or an import file.")
        return

    for raw in cve_ids:
        cve_id = str(raw).upper()
        print_cve_header(cve_id)

        # Load core CVE data
        cve_data = _ensure_cve_loaded(cve_id, fast_mode=fast_mode, config=config)
        display_cve_data(cve_data, None if cve_data else "❌ Unable to load CVE data")
        if not cve_data:
            # Skip to next CVE if core data missing
            continue

        # Fast mode: basic info only
        if fast_mode:
            cve_result = {
                "CVE Data": cve_data,
                "EPSS Data": None,
                "CISA Data": {"cisa_status": "N/A", "ransomware_use": "N/A"},
                "Nuclei Data": None,
                "GitHub Data": None,
                "VulnCheck Data": None,
                "ExploitDB Data": None,
                "PacketStorm Data": {},
                "HackerOne Data": None,
                "Priority": {"Priority": 0},
                "Risk Assessment": None,
            }
            all_results.append(cve_result)
            continue

        # Public exploits
        pub = _public_exploits_bundle(cve_id, config=config, cve_data=cve_data)

        # EPSS
        epss_data = None
        if "epss" in selected:
            epss_data, _ = fetch_epss_score(cve_id)
            display_epss_score(epss_data, None)

        # CISA
        relevant_cisa_data = {"cisa_status": "N/A", "ransomware_use": "N/A"}
        if "cisa" in selected:
            cisa_data, cisa_err = fetch_cisa_data()
            display_cisa_status(cve_id, cisa_data, cisa_err)
            entry = extract_cve_entry(cve_id, cisa_data)
            if entry:
                relevant_cisa_data = {
                    "cisa_status": entry.get("cisa_status", "N/A"),
                    "ransomware_use": entry.get("ransomware_use", "N/A"),
                }

        # HackerOne
        hackerone_data = None
        if "hackerone" in selected:
            hackerone_data, hacker_err = fetch_hackerone_cve_details(cve_id)
            display_hackerone_data(hackerone_data, hacker_err)

        # AI risk assessment
        risk_assessment = None
        if "ai" in selected and ai_provider:
            details = compile_cve_details(cve_id, cve_data, epss_data, relevant_cisa_data, pub)

            # closure for provider call (lazy execution inside display with spinner)
            def _fetch_ai():
                return get_risk_assessment(ai_provider, details, cve_data, config=config)

            # display_ai_risk_assessment now returns the assessment text
            risk_assessment = display_ai_risk_assessment(details, cve_data, ai_provider, _fetch_ai)

        # Priority
        priority = None
        if "prio" in selected:
            priority = calculate_priority(
                cve_id=cve_id,
                cve_data=cve_data,
                epss_data=epss_data,
                github_data=pub.get("github_data"),
                cisa_data=(None if "cisa" not in selected else {"vulnerabilities": [extract_cve_entry(cve_id, fetch_cisa_data()[0])]}),
                vulncheck_data=pub.get("vulncheck_data"),
                exploitdb_data=pub.get("exploitdb_data"),
            )
            display_priority_rating(cve_id, priority)

        # References
        if "references" in selected:
            display_cve_references(cve_data)

        cve_result = {
            "CVE Data": cve_data,
            "EPSS Data": epss_data,
            "CISA Data": relevant_cisa_data,
            "Nuclei Data": pub.get("nuclei_data"),
            "GitHub Data": pub.get("github_data"),
            "VulnCheck Data": pub.get("vulncheck_data"),
            "ExploitDB Data": pub.get("exploitdb_data"),
            "Metasploit Data": pub.get("metasploit_data"),
            "PacketStorm Data": {},  # removed; keep for template compatibility
            "HackerOne Data": hackerone_data,
            "Priority": {"Priority": priority},
            "Risk Assessment": risk_assessment,
        }
        all_results.append(cve_result)

    # Exports
    if export_format == "json":
        filename = export_to_json(all_results, cve_ids)
        print(f"┌───[ 📁 JSON Export ]\n|\n└ Data exported to file: {filename}\n")
    elif export_format == "csv":
        filename = export_to_csv(all_results, cve_ids)
        print(f"┌───[ 📁 CSV Export ]\n|\n└ Data exported to file: {filename}\n")
    elif export_format == "html":
        try:
            filename = export_to_html(all_results, cve_ids)
            print(f"┌───[ 📁 HTML Export ]\n|\n└ Data exported to file: {filename}\n")
        except FileNotFoundError as e:
            print(f"┌───[ 📁 HTML Export ]\n|\n└ {e}\n")


def cli() -> None:
    _configure_console_encoding()
    display_banner()

    parser = argparse.ArgumentParser(
        description="SploitScan: Retrieve and display vulnerability and exploit data for specified CVE ID(s)."
    )
    parser.add_argument(
        "cve_ids",
        type=str,
        nargs="*",
        default=[],
        help="Enter one or more CVE IDs (e.g., CVE-YYYY-NNNNN). This is optional if an import file is provided via -i.",
    )
    parser.add_argument(
        "-e",
        "--export",
        choices=["json", "csv", "html"],
        help="Export the results in the specified format ('json', 'csv', or 'html').",
    )
    parser.add_argument(
        "-t",
        "--type",
        choices=["nessus", "nexpose", "openvas", "docker"],
        help="Specify the type of the import file ('nessus', 'nexpose', 'openvas', or 'docker').",
    )
    parser.add_argument(
        "--ai",
        type=str,
        choices=["openai", "google", "grok", "deepseek"],
        help="Select the AI provider for risk assessment (e.g., 'openai', 'google', 'grok', or 'deepseek').",
    )
    parser.add_argument(
        "-k",
        "--keywords",
        type=str,
        nargs="+",
        help="Search for CVEs related to specific keywords (e.g., product name).",
    )
    parser.add_argument(
        "-local",
        "--local-database",
        dest="local_database",
        action="store_true",
        help="Download the cvelistV5 repository into the local directory. Use the local database over online research if available.",
    )
    parser.add_argument(
        "-f",
        "--fast-mode",
        dest="fast_mode",
        action="store_true",
        help="Enable fast mode: only display basic CVE information without fetching additional exploits or data.",
    )
    parser.add_argument(
        "-m",
        "--methods",
        type=str,
        help="Specify which methods to run, separated by commas (e.g., 'cisa,epss,hackerone,ai,prio,references').",
    )
    parser.add_argument(
        "-i",
        "--import-file",
        type=str,
        help="Path to an import file. When provided, positional CVE IDs can be omitted. The file should be a plain text list with one CVE per line.",
    )
    parser.add_argument("-c", "--config", type=str, help="Path to a custom configuration file.")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output.")

    args = parser.parse_args()

    if args.local_database:
        cfg = load_config(config_path=args.config, debug=args.debug)
        clone_cvelistV5_repo(config=cfg)

    if args.keywords:
        cve_ids = search_cve_by_keywords(args.keywords)
        if not cve_ids:
            raise SystemExit("No valid CVE IDs found for the provided keywords.")
    else:
        cve_ids = args.cve_ids

    main(
        cve_ids,
        export_format=args.export,
        import_file=args.import_file,
        import_type=args.type,
        ai_provider=args.ai,
        config_path=args.config,
        methods=args.methods,
        debug=args.debug,
        fast_mode=args.fast_mode,
    )
