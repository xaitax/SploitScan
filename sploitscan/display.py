"""
Terminal display helpers to keep the original UI and formatting intact.
"""

from __future__ import annotations

import itertools
import sys
import textwrap
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .constants import BLUE, GREEN, YELLOW, ENDC, PRIORITY_COLORS, VERSION
from .metrics import extract_cvss_info
from .utils import parse_iso_date


def display_banner() -> None:
    banner = f"""
{BLUE}
███████╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██████╔╝██║     ██║   ██║██║   ██║   ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║     ███████╗╚██████╔╝██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
v{VERSION} / Alexander Hagenah / @xaitax / ah@primepage.de
{ENDC}
"""
    print(banner)


def print_cve_header(cve_id: str) -> None:
    header = f" CVE ID: {cve_id} "
    line = "═" * len(header)
    print(f"{GREEN}╔{line}╗{ENDC}")
    print(f"{GREEN}║{header}║{ENDC}")
    print(f"{GREEN}╚{line}╝{ENDC}\n")


def _display_section(title: str, lines: Iterable[str]) -> None:
    print(f"┌───[ {BLUE}{title}{ENDC} ]")
    print("|")
    any_line = False
    for ln in lines:
        print(ln)
        any_line = True
    if not any_line:
        print(f"└ ❌ No data found.")
    print()


def _wrap_desc(text: str) -> str:
    wrapped = text.replace("\n\n", " ").replace("  ", " ")
    return textwrap.fill(wrapped, width=100, subsequent_indent=" " * 15)


def display_cve_data(cve_data: Optional[Dict[str, Any]], error: Optional[str] = None) -> None:
    def template(data: Optional[Dict[str, Any]]) -> List[str]:
        if error:
            return [f"└ {error}"]
        if not data or "containers" not in data or "cna" not in data["containers"]:
            return ["└ ❌ No vulnerability data found."]

        cve_item = data["containers"]["cna"]
        published = data.get("cveMetadata", {}).get("datePublished", "")
        published = parse_iso_date(published) if published else ""

        description = next(
            (
                desc.get("value", "")
                for desc in cve_item.get("descriptions", [])
                if desc.get("lang") == "en"
            ),
            "No description available",
        )
        wrapped_description = _wrap_desc(description)

        base_score, base_severity, vector_string = extract_cvss_info(data)
        out = [
            f"├ Published:   {published}",
            f"├ Base Score:  {base_score} ({base_severity})",
            f"├ Vector:      {vector_string}",
            f"└ Description: {wrapped_description}",
        ]
        return out

    _display_section("🔍 Vulnerability information", template(cve_data))


def display_epss_score(epss_data: Optional[Dict[str, Any]], error: Optional[str] = None) -> None:
    def template(data: Optional[Dict[str, Any]]) -> List[str]:
        if error:
            return [f"└ {error}"]
        if not data or "data" not in data or not data["data"]:
            return ["└ ❌ No data found."]
        try:
            epss_score = float(data["data"][0].get("epss", 0))
            return [f"└ EPSS Score:  {epss_score * 100:.2f}% Probability of exploitation."]
        except Exception:
            return ["└ ❌ No data found."]

    _display_section("♾️ Exploit Prediction Score (EPSS)", template(epss_data))


def display_cisa_status(cve_id: str, cisa_data: Optional[Dict[str, Any]], error: Optional[str] = None) -> None:
    def template(data: Optional[Dict[str, Any]]) -> List[str]:
        if error:
            return [f"└ {error}"]
        if not data or "vulnerabilities" not in data:
            return ["└ ❌ No data found."]
        for v in data.get("vulnerabilities", []):
            if v.get("cveID") == cve_id:
                cisa_status = v.get("cisa_status", "N/A")
                ransomware_use = v.get("ransomware_use", "N/A")
                return [f"├ Listed:      {cisa_status}", f"└ Ransomware:  {ransomware_use}"]
        return ["└ ❌ No data found."]

    _display_section("🛡️ CISA KEV Catalog", template(cisa_data))


def display_public_exploits(
    github_data: Optional[Dict[str, Any]],
    vulncheck_data: Optional[Dict[str, Any]],
    exploitdb_data: Optional[List[Dict[str, Any]]],
    nuclei_data: Optional[Dict[str, Any]],
    metasploit_data: Optional[Dict[str, Any]] = None,
    vulncheck_error: Optional[str] = None,
) -> None:
    def template() -> Tuple[List[str], int]:
        total_exploits = 0
        entries: List[str] = []

        # GitHub
        if github_data and github_data.get("pocs"):
            entries.append("├ GitHub")
            sorted_pocs = sorted(github_data["pocs"], key=lambda x: x.get("created_at", ""), reverse=True)
            for poc in sorted_pocs:
                url = poc.get("html_url", "N/A")
                entries.append(f"│  ├ {url}")
                total_exploits += 1
            if entries:
                entries[-1] = entries[-1].replace("├", "└")

        # VulnCheck
        if vulncheck_data and isinstance(vulncheck_data, dict) and vulncheck_data.get("data"):
            entries.append("│")
            entries.append("├ VulnCheck")
            sorted_vulncheck = sorted(
                (xdb for item in vulncheck_data["data"] for xdb in item.get("vulncheck_xdb", [])),
                key=lambda x: x.get("date_added", ""),
                reverse=True,
            )
            for xdb in sorted_vulncheck:
                github_url = xdb.get("clone_ssh_url", "").replace("git@github.com:", "https://github.com/").replace(
                    ".git", ""
                )
                entries.append(f"│  ├ {github_url}")
                total_exploits += 1
            if entries:
                entries[-1] = entries[-1].replace("├", "└")

        if vulncheck_error:
            entries.append("│")
            entries.append(f"└ ❌ VulnCheck Error: {vulncheck_error}")

        # Exploit-DB
        if exploitdb_data:
            entries.append("│")
            entries.append("├ Exploit-DB")
            sorted_exploitdb = sorted(exploitdb_data, key=lambda x: x.get("date", ""), reverse=True)
            for item in sorted_exploitdb:
                url = f"https://www.exploit-db.com/exploits/{item['id']}"
                entries.append(f"│  ├ {url}")
                total_exploits += 1
            if entries:
                entries[-1] = entries[-1].replace("├", "└")

        # Metasploit
        if metasploit_data and isinstance(metasploit_data, dict) and metasploit_data.get("modules"):
            entries.append("│")
            entries.append("├ Metasploit")
            for m in metasploit_data.get("modules", []):
                if not isinstance(m, dict):
                    continue
                fullname = m.get("fullname", "N/A")
                rank_label = m.get("rank_label") or ""
                label = f"{fullname} [{rank_label}]" if rank_label else fullname
                url = m.get("url") or ""
                if url:
                    entries.append(f"│  ├ {url}")
                else:
                    entries.append(f"│  ├ {label}")
                total_exploits += 1
            if entries:
                entries[-1] = entries[-1].replace("├", "└")

        # Nuclei
        if nuclei_data and (nuclei_data.get("file_path") or nuclei_data.get("raw_url")):
            entries.append("│")
            entries.append("├ Nuclei")
            url = nuclei_data.get("raw_url")
            if not url and nuclei_data.get("file_path"):
                base_url = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/"
                url = f"{base_url}{nuclei_data['file_path']}"
            if url:
                entries.append(f"│  ├ {url}")
                total_exploits += 1
            if entries:
                entries[-1] = entries[-1].replace("├", "└")

        if not entries:
            return (["└ ❌ No data found."], total_exploits)

        return (entries, total_exploits)

    exploits, total = template()
    print(f"┌───[ {BLUE}💣 Public Exploits (Total: {total}){ENDC} ]")
    if exploits:
        print("|")
        for line in exploits:
            print(line)
        print()
    else:
        print("|")
        print(f"└ ❌ No data found.\n")


def display_hackerone_data(hackerone_data: Optional[Dict[str, Any]], error: Optional[str] = None) -> None:
    def template(data: Optional[Dict[str, Any]]) -> List[str]:
        if error:
            return [f"└ {error}"]
        if not data or "data" not in data or "cve_entry" not in data["data"]:
            return ["└ ❌ No data found."]

        cve_entry = data["data"].get("cve_entry")
        if not cve_entry:
            return ["└ ❌ No data found."]

        rank = cve_entry.get("rank", "N/A")
        reports_submitted_count = cve_entry.get("reports_submitted_count", "N/A")
        severity_unknown = cve_entry.get("severity_count_unknown", 0)
        severity_none = cve_entry.get("severity_count_none", 0)
        severity_low = cve_entry.get("severity_count_low", 0)
        severity_medium = cve_entry.get("severity_count_medium", 0)
        severity_high = cve_entry.get("severity_count_high", 0)
        severity_critical = cve_entry.get("severity_count_critical", 0)

        severity_display = (
            f"Unknown: {severity_unknown} / None: {severity_none} / Low: {severity_low} / "
            f"Medium: {severity_medium} / High: {severity_high} / Critical: {severity_critical}"
        )
        return [f"├ Rank:        {rank}", f"├ Reports:     {reports_submitted_count}", f"└ Severity:    {severity_display}"]

    _display_section("🕵️ HackerOne Hacktivity", template(hackerone_data))


def display_cve_references(cve_data: Optional[Dict[str, Any]], error: Optional[str] = None) -> None:
    def template(data: Optional[Dict[str, Any]]) -> List[str]:
        if error:
            return [f"└ {error}"]
        if not data or "containers" not in data or "cna" not in data["containers"]:
            return ["└ ❌ No data found."]
        refs = data["containers"]["cna"].get("references", [])
        if refs:
            lines = [f"├ {ref.get('url')}" for ref in refs[:-1]]
            lines.append(f"└ {refs[-1].get('url')}")
            return lines
        return ["└ ❌ No further references found."]

    _display_section("📚 Further References", template(cve_data))


def display_priority_rating(cve_id: str, priority: Optional[str]) -> None:
    def template(data: Optional[Dict[str, Any]]) -> List[str]:
        if not data or "priority" not in data or not data["priority"]:
            return ["└ ❌ No data found."]
        priority_color = PRIORITY_COLORS.get(data["priority"], ENDC)
        return [f"└ Priority:     {priority_color}{data['priority']}{ENDC}"]

    if priority is None:
        _display_section("⚠️ Patching Priority Rating", template(None))
    else:
        _display_section("⚠️ Patching Priority Rating", template({"priority": priority}))


def display_ai_risk_assessment(cve_details: str, cve_data: Dict[str, Any], ai_provider: str, fetch_fn) -> None:
    """
    Render the AI risk assessment with a spinner.

    fetch_fn: Callable[[str], str] - a function that returns the assessment text for a given prompt.
    This indirection avoids tight coupling to specific providers in the display layer.
    """
    # Spinner using an Event (no globals)
    stop_event = threading.Event()

    def spinner_animation(message: str) -> None:
        spinner = itertools.cycle(["|", "/", "-", "\\"])
        while not stop_event.is_set():
            sys.stdout.write(f"\r{message} {next(spinner)}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * (len(message) + 2) + "\r")
        sys.stdout.flush()

    assessment: Optional[str] = None

    def get_assessment():
        nonlocal assessment
        try:
            assessment = fetch_fn()
        except Exception as e:
            assessment = f"❌ Error fetching AI response: {e}"
        finally:
            stop_event.set()

    print("┌───[ 🤖 AI-Powered Risk Assessment ]")
    print("|")
    spinner_thread = threading.Thread(target=spinner_animation, args=(f"| Loading {ai_provider} risk assessment...",))
    spinner_thread.start()
    worker_thread = threading.Thread(target=get_assessment)
    worker_thread.start()
    worker_thread.join()
    spinner_thread.join()

    print("|")
    if assessment:
        sections = assessment.split("\n\n")
        for section in sections:
            section = section.strip()
            if not section:
                continue
            if section.startswith(("1. ", "2. ", "3. ", "4. ")):
                header = section.split("\n")[0].strip()
                print(f"| {header}")
                print("| " + "-" * (len(header) + 1))
                content = "\n".join(section.split("\n")[1:]).strip()
                wrapped_content = textwrap.fill(content, width=100, initial_indent="| ", subsequent_indent="| ")
                print(wrapped_content)
            else:
                wrapped_content = textwrap.fill(section, width=100, initial_indent="| ", subsequent_indent="| ")
                print(wrapped_content)
            print("|")
    else:
        print("| ❌ No AI Risk Assessment could be retrieved.")
        print("|")

    print("└────────────────────────────────────────\n")
    return assessment or ""
