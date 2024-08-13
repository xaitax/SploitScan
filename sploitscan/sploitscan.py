#!/usr/bin/env python3

import requests
import argparse
import datetime
import textwrap
import threading
import itertools
import time
import json
import sys
import os
import csv
import re
import xml.etree.ElementTree as ET
from openai import OpenAI
from jinja2 import Environment, FileSystemLoader


VERSION = "0.10.5"

BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
ENDC = "\033[0m"

CVE_GITHUB_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
EPSS_API_URL = "https://api.first.org/data/v1/epss?cve={cve_id}"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NUCLEI_URL = (
    "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
)
GITHUB_API_URL = "https://poc-in-github.motikan2010.net/api/v1/"
VULNCHECK_API_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
EXPLOITDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv?ref_type=heads"
PACKETSTORM_URL = "https://packetstormsecurity.com/search/?q={cve_id}"
HACKERONE_URL = "https://hackerone.com/graphql"

CVSS_THRESHOLD = 6.0
EPSS_THRESHOLD = 0.2

PRIORITY_COLORS = {
    "A+": "\033[91m",
    "A": "\033[31m",
    "B": "\033[93m",
    "C": "\033[94m",
    "D": "\033[92m",
}


def fetch_data(url, params=None, headers=None):
    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        return f"❌ Error fetching data from {url}: {e}"


def fetch_json_data(url, params=None, headers=None):
    response = fetch_data(url, params, headers)
    if isinstance(response, str):
        return None, response
    try:
        return response.json(), None
    except json.JSONDecodeError as e:
        return None, f"❌ Error parsing JSON data from {url}: {e}"


def fetch_github_cve_data(cve_id):
    cve_year = cve_id.split("-")[1]
    cve_num = int(cve_id.split("-")[2])
    url = f"{CVE_GITHUB_URL}/{cve_year}/{cve_num // 1000}xxx/{cve_id}.json"
    return fetch_json_data(url)


def fetch_epss_score(cve_id):
    return fetch_json_data(EPSS_API_URL.format(cve_id=cve_id))


def fetch_cisa_data():
    data, error = fetch_json_data(CISA_URL)
    if data and "vulnerabilities" in data:
        for vulnerability in data["vulnerabilities"]:
            vulnerability["cisa_status"] = "Yes"
            vulnerability["ransomware_use"] = vulnerability.get(
                "knownRansomwareCampaignUse", "Unknown"
            )
    return data, error


def fetch_nuclei_data(cve_id):
    response = fetch_data(NUCLEI_URL)
    if isinstance(response, str):
        return None, response
    try:
        for line in response.iter_lines():
            if line:
                template = json.loads(line.decode("utf-8"))
                if template["ID"] == cve_id:
                    return template, None
    except json.JSONDecodeError as e:
        return None, f"❌ Error parsing JSON data from {NUCLEI_URL}: {e}"
    return None, None


def fetch_vulncheck_data(cve_id):
    vulncheck_api_key = config.get("vulncheck_api_key")
    if not vulncheck_api_key:
        return None, None

    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {vulncheck_api_key}",
    }

    response = fetch_data(VULNCHECK_API_URL, params={"cve": cve_id}, headers=headers)
    if isinstance(response, str):
        return None, response
    try:
        json_data = response.json()
        return json_data, None
    except json.JSONDecodeError as e:
        return None, f"❌ Error parsing JSON data from VulnCheck: {e}"

def fetch_exploitdb_data(cve_id):
    response = fetch_data(EXPLOITDB_URL)
    if isinstance(response, str):
        return [], response
    try:
        decoded_content = response.content.decode("utf-8")
        csv_reader = csv.reader(decoded_content.splitlines(), delimiter=",")
        header = next(csv_reader)
        codes_index = header.index("codes")
        return [
            {"id": row[0], "date": row[3]}
            for row in csv_reader
            if cve_id in row[codes_index].split(";")
        ], None
    except csv.Error as e:
        return [], f"❌ Error parsing CSV data from {EXPLOITDB_URL}: {e}"


def fetch_packetstorm_data(cve_id):
    response = fetch_data(PACKETSTORM_URL.format(cve_id=cve_id))
    if isinstance(response, str):
        return {}, response
    return (
        {"packetstorm_url": PACKETSTORM_URL.format(cve_id=cve_id)}
        if "No Results Found" not in response.text
        else {}
    ), None

def fetch_hackerone_cve_details(cve_id):
    headers = {
        'content-type': 'application/json'
    }
    payload = {
        "operationName": "CveDiscoveryDetailedViewCveEntry",
        "variables": {
            "cve_id": cve_id
        },
        "query": """
        query CveDiscoveryDetailedViewCveEntry($cve_id: String!) {
            cve_entry(cve_id: $cve_id) {
                rank
                reports_submitted_count
                severity_count_unknown
                severity_count_none
                severity_count_low
                severity_count_medium
                severity_count_high
                severity_count_critical
                __typename
            }
        }
        """
    }

    response = requests.post(HACKERONE_URL, headers=headers, json=payload)
    
    if response.status_code == 200:
        try:
            data = response.json()
            if 'data' in data and 'cve_entry' in data['data']:
                return data, None
            else:
                return None, "❌ No HackerOne data found for this CVE."
        except json.JSONDecodeError as e:
            return None, f"❌ Error parsing JSON data from HackerOne: {e}"
    else:
        return None, f"❌ Error fetching data from HackerOne: {response.status_code}: {response.text}"


def display_data(title, data, template, error=None):
    print(f"┌───[ {BLUE}{title}{ENDC} ]")
    if error:
        print("|")
        print(f"└ {error}\n")
        return
    if data:
        print(f"|")
        for line in template(data):
            print(line)
        print()
    else:
        print("|")
        print(f"└ ❌ No data found.\n")


def display_cve_data(cve_data, error=None):
    def template(data):
        if not data or "containers" not in data or "cna" not in data["containers"]:
            return ["└ ❌ No vulnerability data found."]

        cve_item = data["containers"]["cna"]
        published = data["cveMetadata"].get("datePublished", "")
        if published:
            published_date = datetime.datetime.fromisoformat(published.rstrip("Z"))
            published = published_date.strftime("%Y-%m-%d")
        description = (
            next(
                (
                    desc["value"]
                    for desc in cve_item.get("descriptions", [])
                    if desc["lang"] == "en"
                ),
                "No description available",
            )
            .replace("\n\n", " ")
            .replace("  ", " ")
        )
        wrapped_description = textwrap.fill(
            description, width=100, subsequent_indent=" " * 15
        )

        metrics = cve_item.get("metrics", [])
        baseScore, baseSeverity, vectorString = "N/A", "N/A", "N/A"

        for metric in metrics:
            cvss_data = metric.get("cvssV3_1") or metric.get("cvssV3")
            if cvss_data:
                baseScore = cvss_data.get("baseScore", "N/A")
                baseSeverity = cvss_data.get("baseSeverity", "N/A")
                vectorString = cvss_data.get("vectorString", "N/A")
                if baseScore != "N/A":
                    break
        
        if baseScore == "N/A":
            adp = data["containers"].get("adp", [])
            for adp_entry in adp:
                for metric in adp_entry.get("metrics", []):
                    cvss_data = metric.get("cvssV3_1") or metric.get("cvssV3")
                    if cvss_data:
                        baseScore = cvss_data.get("baseScore", "N/A")
                        baseSeverity = cvss_data.get("baseSeverity", "N/A")
                        vectorString = cvss_data.get("vectorString", "N/A")
                        if baseScore != "N/A":
                            break
                if baseScore != "N/A":
                    break

        return [
            f"├ Published:   {published}",
            f"├ Base Score:  {baseScore} ({baseSeverity})",
            f"├ Vector:      {vectorString}",
            f"└ Description: {wrapped_description}",
        ]

    display_data("🔍 Vulnerability information", cve_data, template, error)


def display_epss_score(epss_data, error=None):
    def template(data):
        if not data or "data" not in data or not data["data"]:
            return ["└ ❌ No data found."]

        epss_score = data["data"][0].get("epss", "N/A")
        return (
            [
                f"└ EPSS Score:  {float(epss_score) * 100:.2f}% Probability of exploitation."
            ]
            if epss_score != "N/A"
            else []
        )

    display_data("♾️ Exploit Prediction Score (EPSS)",
                 epss_data, template, error)


def display_cisa_status(cve_id, cisa_data, error=None):
    def template(data):
        if not data or "vulnerabilities" not in data or not data["vulnerabilities"]:
            return ["└ ❌ No data found."]

        for vulnerability in data["vulnerabilities"]:
            if vulnerability["cveID"] == cve_id:
                cisa_status = vulnerability["cisa_status"]
                ransomware_use = vulnerability["ransomware_use"]
                return [
                    f"├ Listed:      {cisa_status}",
                    f"└ Ransomware:  {ransomware_use}",
                ]

        return ["└ ❌ No data found."]

    display_data("🛡️ CISA KEV Catalog", cisa_data, template, error)


def display_public_exploits(github_data, vulncheck_data, exploitdb_data, packetstorm_data, nuclei_data, vulncheck_error=None):
    def template():
        total_exploits = 0
        entries = []

        if github_data and github_data.get("pocs"):
            entries.append("├ GitHub")
            sorted_pocs = sorted(github_data["pocs"], key=lambda x: x.get("created_at", ""), reverse=True) if github_data["pocs"] else []

            for poc in sorted_pocs:
                created_at = poc.get("created_at", "N/A")
                if created_at != "N/A":
                    created_date = datetime.datetime.fromisoformat(created_at)
                    created_at = created_date.strftime("%Y-%m-%d")
                entries.append(f"│  ├ Date: {created_at} - {poc.get('html_url', 'N/A')}")
                total_exploits += 1
            entries[-1] = entries[-1].replace("├", "└")

        if vulncheck_data and isinstance(vulncheck_data, dict) and vulncheck_data.get("data"):
            entries.append("│")
            entries.append("├ VulnCheck")
            sorted_vulncheck = sorted(
                (xdb for item in vulncheck_data["data"] for xdb in item.get("vulncheck_xdb", [])),
                key=lambda x: x.get("date_added", ""),
                reverse=True
            )
            for xdb in sorted_vulncheck:
                date_added = xdb.get("date_added", "N/A")
                if date_added != "N/A":
                    try:
                        date_added = datetime.datetime.fromisoformat(date_added.rstrip("Z")).strftime("%Y-%m-%d")
                    except ValueError:
                        pass
                github_url = xdb.get("clone_ssh_url", "").replace("git@github.com:", "https://github.com/").replace(".git", "")
                entries.append(f"│  ├ Date: {date_added} - {github_url}")
                total_exploits += 1
            entries[-1] = entries[-1].replace("├", "└")

        if vulncheck_error:
            entries.append("│")
            entries.append(f"└ ❌ VulnCheck Error: {vulncheck_error}")

        if exploitdb_data:
            entries.append("│")
            entries.append("├ Exploit-DB")
            sorted_exploitdb = sorted(exploitdb_data, key=lambda x: x["date"], reverse=True)
            for item in sorted_exploitdb:
                url = f"https://www.exploit-db.com/exploits/{item['id']}"
                entries.append(f"│  ├ Date: {item['date']} - {url}")
                total_exploits += 1
            entries[-1] = entries[-1].replace("├", "└")

        other_entries = []
        if packetstorm_data and packetstorm_data.get("packetstorm_url"):
            other_entries.append(f"PacketStorm: {packetstorm_data['packetstorm_url']}")
        if nuclei_data and nuclei_data.get("file_path"):
            base_url = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/"
            file_path = nuclei_data["file_path"]
            full_url = f"{base_url}{file_path}"
            other_entries.append(f"Nuclei: {full_url}")
        if other_entries:
            entries.append("│")
            entries.append("└ Other")
            for index, entry in enumerate(other_entries[:-1]):
                entries.append(f"   ├ {entry}")
            entries.append(f"   └ {other_entries[-1]}")

        if not entries:
            return ["└ ❌ No data found."], total_exploits

        return entries, total_exploits

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


def display_hackerone_data(hackerone_data, error=None):
    def template(data):
        if not data or "data" not in data or "cve_entry" not in data["data"]:
            return ["└ ❌ No data found."]

        cve_entry = data["data"]["cve_entry"]
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
        
        severity_display = f"Unknown: {severity_unknown} / None: {severity_none} / Low: {severity_low} / Medium: {severity_medium} / High: {severity_high} / Critical: {severity_critical}"
        
        return [
            f"├ Rank:        {rank}",
            f"├ Reports:     {reports_submitted_count}",
            f"└ Severity:    {severity_display}",
        ]

    display_data("🕵️ HackerOne Hacktivity", hackerone_data, template, error)


def display_cve_references(cve_data, error=None):
    def template(data):
        if not data or "containers" not in data or "cna" not in data["containers"]:
            return ["└ ❌ No data found."]

        references = data["containers"]["cna"].get("references", [])
        return (
            [f"├ {ref['url']}" for ref in references[:-1]]
            + [f"└ {references[-1]['url']}"]
            if references
            else ["└ ❌ No further references found."]
        )

    display_data("📚 Further References", cve_data, template, error)


def calculate_priority(
    cve_id, cve_data, epss_data, github_data, cisa_data, vulncheck_data, exploitdb_data
):
    cvss_score, epss_score = 0, 0
    try:
        metrics = cve_data["containers"]["cna"]["metrics"]
        for metric in metrics:
            if "cvssV3_1" in metric:
                cvss_score = float(metric["cvssV3_1"]["baseScore"])
                break
    except (KeyError, IndexError, TypeError):
        pass
    try:
        epss_score = (
            float(epss_data["data"][0]["epss"])
            if epss_data and "data" in epss_data
            else 0
        )
    except (KeyError, IndexError, TypeError):
        pass
    in_cisa_kev = (
        any(vuln["cveID"] == cve_id for vuln in cisa_data.get(
            "vulnerabilities", []))
        if cisa_data
        else False
    )
    has_public_exploits = (
        bool(github_data.get("pocs"))
        if github_data
        else (
            False or bool(vulncheck_data.get("data"))
            if vulncheck_data
            else False or bool(exploitdb_data)
        )
    )

    if not (cvss_score or epss_score or in_cisa_kev or has_public_exploits):
        return None

    if in_cisa_kev or has_public_exploits:
        return "A+"
    if cvss_score >= CVSS_THRESHOLD and epss_score >= EPSS_THRESHOLD:
        return "A"
    if cvss_score >= CVSS_THRESHOLD:
        return "B"
    if epss_score >= EPSS_THRESHOLD:
        return "C"
    return "D"


def display_priority_rating(cve_id, priority):
    def template(data):
        if not data or "priority" not in data or not data["priority"]:
            return ["└ ❌ No data found."]

        priority_color = PRIORITY_COLORS.get(data["priority"], ENDC)
        return [f"└ Priority:     {priority_color}{data['priority']}{ENDC}"]

    if priority is None:
        display_data("⚠️ Patching Priority Rating", None, template)
    else:
        display_data("⚠️ Patching Priority Rating", {
                     "priority": priority}, template)


def load_config(config_path=None, debug=False):
    default_config = {"vulncheck_api_key": None, "openai_api_key": None}
    config_env_var = "SPLOITSCAN_CONFIG_PATH"

    config_paths = [config_path] if config_path else []
    config_paths += [
        os.getenv(config_env_var),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json"),
        os.path.expanduser("~/.sploitscan/config.json"),
        os.path.expanduser("~/.config/sploitscan/config.json"),
        os.path.expanduser("~/Library/Application Support/sploitscan/config.json"),
        os.path.join(os.getenv("APPDATA", ""), "sploitscan", "config.json"),
        "/etc/sploitscan/config.json",
    ]

    config_paths = [path for path in config_paths if path]

    for path in config_paths:
        if path and os.path.exists(path):
            try:
                if debug:
                    print(f"⚠️ Attempting to load config file from: {path}")
                with open(path, "r", encoding="utf-8") as file:
                    config = json.load(file)
                    if debug:
                        print(f"⚠️ Successfully loaded config file: {path}")
                    return config
            except json.JSONDecodeError as e:
                print(f"⚠️ Error decoding JSON from the config file {path}: {e}")
            except Exception as e:
                print(f"⚠️ Unexpected error reading config file {path}: {e}")

    print("⚠️ Config file not found in any checked locations, using default settings.")
    return default_config


def get_risk_assessment(cve_details, cve_data):
    api_key = config.get("openai_api_key")

    if not api_key:
        return "❌ OpenAI API key is not configured correctly."

    client = OpenAI(api_key=api_key)

    prompt = f"""
    You are a security analyst. Analyze the following CVE details and provide a detailed risk assessment, potential attack scenarios, mitigation recommendations, and an executive summary. Ensure the output is formatted for a console display without any markdown, NO MARKDOWN, and the headers are clearly delineated with proper formatting as specified! Output only proper free flowing text and no lists as this won't be properly displayed in the console.

    CVE Details:
    {cve_details}

    Full CVE Data:
    {json.dumps(cve_data, indent=4)}

    Format the output exactly as follows:

    1. Risk Assessment
    Provide a detailed risk assessment including the nature of the vulnerability & its business impact. Describe the likelihood and ease of exploitation, and potential impacts on confidentiality, integrity, and availability.

    2. Potential Attack Scenarios
    Describe at least one potential attack scenarios that leverage this vulnerability. Each scenario should include a detailed description of the attack vector, the attack process, and the potential outcomes.

    3. Mitigation Recommendations
    Provide specific, actionable mitigation recommendations. Include immediate actions such as patching. Provide links to relevant resources where applicable.

    4. Executive Summary
    Summarize the vulnerability, its potential impacts, and the importance of taking action. Highlight key points from the risk assessment, attack scenarios, and mitigation recommendations. This summary should be accessible to non-technical stakeholders, emphasizing the business impact and urgency of addressing the vulnerability.
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a security analyst."},
                {"role": "user", "content": prompt},
            ],
        )
        result = response.choices[0].message.content.strip()
        return result
    except Exception as e:
        return f"❌ Error fetching data from OpenAI: {e}"


def display_ai_risk_assessment(cve_details, cve_data):
    def spinner_animation(message):
        spinner = itertools.cycle(['|', '/', '-', '\\'])
        while not stop_spinner:
            sys.stdout.write(f'\r{message} {next(spinner)}')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * (len(message) + 2) + '\r')
        sys.stdout.flush()

    def get_risk_assessment_thread():
        nonlocal assessment
        assessment = get_risk_assessment(cve_details, cve_data)
        global stop_spinner
        stop_spinner = True

    global stop_spinner
    stop_spinner = False
    assessment = None

    print("┌───[ 🤖 AI-Powered Risk Assessment ]")
    print("|")

    spinner_thread = threading.Thread(target=spinner_animation, args=("| Loading OpenAI risk assessment... ",))
    spinner_thread.start()

    assessment_thread = threading.Thread(target=get_risk_assessment_thread)
    assessment_thread.start()

    assessment_thread.join()

    spinner_thread.join()

    print("|")

    if assessment:
        sections = assessment.split("\n\n")

        for section in sections:
            section = section.strip()
            if section:
                if section.startswith(("1. ", "2. ", "3. ", "4. ")):
                    header = section.split("\n")[0].strip()
                    print(f"| {header}")
                    print("| " + "-" * (len(header) + 1))

                    content = "\n".join(section.split("\n")[1:]).strip()
                    wrapped_content = textwrap.fill(
                        content, width=100, initial_indent="| ", subsequent_indent="| "
                    )
                    print(wrapped_content)
                else:
                    wrapped_content = textwrap.fill(
                        section, width=100, initial_indent="| ", subsequent_indent="| "
                    )
                    print(wrapped_content)
                print("|")

    print("└────────────────────────────────────────\n")



def import_vulnerability_data(file_path, file_type):
    if not os.path.exists(file_path):
        print(f"❌ Error: The file '{file_path}' does not exist.")
        return []
    if file_type == "nessus":
        return import_nessus(file_path)
    if file_type == "nexpose":
        return import_nexpose(file_path)
    if file_type == "openvas":
        return import_openvas(file_path)
    if file_type == "docker":
        return import_docker(file_path)
    print(f"❌ Unsupported file type: {file_type}")
    return []


def import_nessus(file_path):
    def parse_nessus_file(path):
        tree = ET.parse(path)
        root = tree.getroot()
        return [
            cve.text.strip().upper()
            for report_item in root.findall(".//ReportItem")
            for cve in report_item.findall("cve")
            if is_valid_cve_id(cve.text.strip().upper())
        ]

    return import_file(file_path, parse_nessus_file)


def import_nexpose(file_path):
    def parse_nexpose_file(path):
        tree = ET.parse(path)
        root = tree.getroot()
        return [
            link.get("LinkTitle").upper()
            for link in root.findall(".//URLLink")
            if link.get("LinkTitle", "").startswith("CVE-")
        ]

    return import_file(file_path, parse_nexpose_file)


def import_openvas(file_path):
    def parse_openvas_file(path):
        tree = ET.parse(path)
        root = tree.getroot()
        return [
            ref.attrib.get("id").upper()
            for ref in root.findall(".//ref[@type='cve']")
            if is_valid_cve_id(ref.attrib.get("id").upper())
        ]

    return import_file(file_path, parse_openvas_file)


def import_docker(file_path):
    def parse_docker_file(path):
        with open(path, "r") as file:
            data = json.load(file)
        return [
            rule.get("id", "").upper()
            for run in data.get("runs", [])
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
            if rule.get("id", "").startswith("CVE-")
        ]

    return import_file(file_path, parse_docker_file)


def import_file(file_path, parse_function):
    try:
        cve_ids = parse_function(file_path)
        unique_cve_ids = list(set(cve_ids))
        print(
            YELLOW
            + f"📥 Successfully imported {len(unique_cve_ids)} CVE(s) from '{file_path}'.\n"
        )
        return unique_cve_ids
    except ET.ParseError as e:
        print(f"❌ Error parsing the file '{file_path}': {e}")
    except json.JSONDecodeError as e:
        print(f"❌ Error parsing the JSON file '{file_path}': {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred while processing '{file_path}': {e}")
    return []


def is_valid_cve_id(cve_id):
    return re.match(r"CVE-\d{4}-\d{4,7}$", cve_id) is not None


def generate_filename(cve_ids, extension):
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    cve_part = "_".join(cve_ids[:3]) + \
        ("_and_more" if len(cve_ids) > 3 else "")
    return f"{timestamp}_{cve_part}_export.{extension}"


def datetimeformat(value, format="%Y-%m-%d"):
    return datetime.datetime.fromisoformat(value.rstrip("Z")).strftime(format)


def export_to_html(all_results, cve_ids):
    def template(data):
        base_path = os.path.dirname(os.path.abspath(__file__))
        template_paths = [
            os.path.join(base_path, "templates"),
            os.path.expanduser("~/.sploitscan/templates"),
            os.path.expanduser("~/.config/sploitscan/templates"),
            "/etc/sploitscan/templates",
        ]

        for path in template_paths:
            if os.path.exists(os.path.join(path, "report_template.html")):
                env = Environment(loader=FileSystemLoader(path))
                break
        else:
            print(
                "❌ HTML template 'report_template.html' not found in any checked locations.")
            return ["❌ Error exporting to HTML: template not found"]

        env.filters["datetimeformat"] = datetimeformat
        template = env.get_template("report_template.html")
        filename = generate_filename(cve_ids, "html")
        output = template.render(cve_data=handle_cvss(data))

        with open(filename, "w", encoding="utf-8") as file:
            file.write(output)

        return [f"└ Data exported to file: {filename}"]

    def handle_cvss(data):
        for result in data:
            result["Public Exploits Total"] = sum([
                len(result.get("GitHub Data", {}).get("pocs", [])),
                sum(len(item.get("vulncheck_xdb", [])) for item in result.get("VulnCheck Data", {}).get("data", [])),
                len(result.get("ExploitDB Data", []))
            ])
            
            if "GitHub Data" in result and "pocs" in result["GitHub Data"]:
                result["GitHub Data"]["pocs"] = sorted(result["GitHub Data"]["pocs"], key=lambda x: x.get("created_at", ""), reverse=True)
            
            if "VulnCheck Data" in result and "data" in result["VulnCheck Data"]:
                for item in result["VulnCheck Data"]["data"]:
                    if "vulncheck_xdb" in item:
                        item["vulncheck_xdb"] = sorted(item["vulncheck_xdb"], key=lambda x: x.get("date_added", ""), reverse=True)
            
            if "ExploitDB Data" in result:
                result["ExploitDB Data"] = sorted(result["ExploitDB Data"], key=lambda x: x.get("date", ""), reverse=True)
            
            if "EPSS Data" in result and "data" in result["EPSS Data"] and len(result["EPSS Data"]["data"]) > 0:
                result["EPSS Data"]["data"][0]["epss"] = try_parse_float(result["EPSS Data"]["data"][0].get("epss"))
            
            metrics = result.get("CVE Data", {}).get("containers", {}).get("cna", {}).get("metrics", [])
            for metric in metrics:
                cvss_data = metric.get("cvssV3_1", metric.get("cvssV3"))
                if cvss_data:
                    cvss_data["baseScore"] = try_parse_float(cvss_data.get("baseScore"))
                    cvss_data["baseSeverity"] = str(cvss_data.get("baseSeverity", "N/A"))
                    cvss_data["vectorString"] = str(cvss_data.get("vectorString", "N/A"))
                else:
                    metric["cvssV3_1"] = {
                        "baseScore": 0.0, "baseSeverity": "N/A", "vectorString": "N/A"}
        return data

    def try_parse_float(value):
        try:
            return float(value)
        except (ValueError, TypeError):
            return 0.0

    try:
        display_data("📁 HTML Export", all_results, template)
    except Exception as e:
        print(f"❌ Error exporting to HTML: {e}")


def export_to_json(all_results, cve_ids):
    def template(data):
        filename = generate_filename(cve_ids, "json")
        with open(filename, "w") as file:
            json.dump(data, file, indent=4)
        return [f"└ Data exported to file: {filename}"]

    display_data("📁 JSON Export", all_results, template)


def export_to_csv(all_results, cve_ids):
    def template(data):
        filename = generate_filename(cve_ids, "csv")
        keys = list(data[0].keys()) + ["Risk Assessment"]
        with open(filename, "w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=keys)
            writer.writeheader()
            for item in data:
                item["Risk Assessment"] = item.get("Risk Assessment", "N/A")
                writer.writerow(item)
        return [f"└ Data exported to CSV: {filename}"]

    display_data("📁 CSV Export", all_results, template)


def display_banner():
    banner = f"""
███████╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██████╔╝██║     ██║   ██║██║   ██║   ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║     ███████╗╚██████╔╝██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
v{VERSION} / Alexander Hagenah / @xaitax / ah@primepage.de
"""
    print(BLUE + banner + ENDC)


def print_cve_header(cve_id):
    header = f" CVE ID: {cve_id} "
    line = "═" * len(header)
    print(f"{GREEN}╔{line}╗{ENDC}")
    print(f"{GREEN}║{header}║{ENDC}")
    print(f"{GREEN}╚{line}╝{ENDC}\n")

def fetch_and_display_cve_data(cve_id):
    cve_data, cve_error = fetch_github_cve_data(cve_id)
    display_cve_data(cve_data, cve_error)
    return cve_data

def fetch_and_display_epss_score(cve_id):
    epss_data, epss_error = fetch_epss_score(cve_id)
    display_epss_score(epss_data, epss_error)
    return epss_data

def fetch_and_display_cisa_status(cve_id):
    cisa_data, cisa_error = fetch_cisa_data()
    display_cisa_status(cve_id, cisa_data, cisa_error)
    relevant_cisa_data = next(
        (item for item in cisa_data.get("vulnerabilities", []) if item["cveID"] == cve_id),
        None,
    )
    return relevant_cisa_data

def fetch_and_display_public_exploits(cve_id):
    github_data, github_error = fetch_json_data(GITHUB_API_URL, params={"cve_id": cve_id})
    vulncheck_data, vulncheck_error = fetch_vulncheck_data(cve_id)
    exploitdb_data, exploitdb_error = fetch_exploitdb_data(cve_id)
    packetstorm_data, packetstorm_error = fetch_packetstorm_data(cve_id)
    nuclei_data, nuclei_error = fetch_nuclei_data(cve_id)
    
    display_public_exploits(github_data, vulncheck_data, exploitdb_data, packetstorm_data, nuclei_data, vulncheck_error)
    
    return {
        "github_data": github_data,
        "vulncheck_data": vulncheck_data if isinstance(vulncheck_data, dict) else {},
        "exploitdb_data": exploitdb_data,
        "packetstorm_data": packetstorm_data,
        "nuclei_data": nuclei_data
    }

def fetch_and_display_hackerone_data(cve_id):
    hackerone_data, hackerone_error = fetch_hackerone_cve_details(cve_id)
    display_hackerone_data(hackerone_data, hackerone_error)
    return hackerone_data

def compile_cve_details(cve_id, cve_data, epss_data, relevant_cisa_data, public_exploits):
    published = cve_data["cveMetadata"].get("datePublished", "N/A")
    if published != "N/A":
        published = datetime.datetime.fromisoformat(published.rstrip("Z")).strftime("%Y-%m-%d")

    description = (
        next(
            (desc["value"] for desc in cve_data["containers"]["cna"].get("descriptions", []) if desc["lang"] == "en"),
            "No description available",
        )
        .replace("\n\n", " ")
        .replace("  ", " ")
    )
    metrics = cve_data["containers"]["cna"].get("metrics", [])
    baseScore, baseSeverity, vectorString = "N/A", "N/A", "N/A"
    for metric in metrics:
        if "cvssV3_1" in metric:
            cvss_data = metric["cvssV3_1"]
            baseScore = cvss_data.get("baseScore", "N/A")
            baseSeverity = cvss_data.get("baseSeverity", "N/A")
            vectorString = cvss_data.get("vectorString", "N/A")
            break

    epss_score = epss_data["data"][0].get("epss", "N/A") if epss_data and "data" in epss_data and epss_data["data"] else "N/A"


    cisa_status = relevant_cisa_data["cisa_status"] if relevant_cisa_data else "N/A"
    ransomware_use = relevant_cisa_data["ransomware_use"] if relevant_cisa_data else "N/A"

    github_exploits = "\n".join(
        [f"{poc['created_at']}: {poc['html_url']}" for poc in public_exploits["github_data"].get("pocs", [])]
    ) if public_exploits["github_data"] else "N/A"

    vulncheck_exploits = "\n".join(
        [f"{xdb['date_added']}: {xdb['clone_ssh_url'].replace('git@github.com:', 'https://github.com/').replace('.git', '')}"
         for item in public_exploits["vulncheck_data"].get("data", [])
         for xdb in item.get("vulncheck_xdb", [])]
    ) if public_exploits["vulncheck_data"] else "N/A"

    packetstorm_url = public_exploits["packetstorm_data"].get("packetstorm_url", "N/A")

    nuclei_url = f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/{public_exploits['nuclei_data']['file_path']}" if public_exploits["nuclei_data"] and "file_path" in public_exploits["nuclei_data"] else "N/A"

    references_list = cve_data["containers"]["cna"].get("references", [])
    references = "\n".join([ref["url"] for ref in cve_data["containers"]["cna"].get("references", [])]) if cve_data else "N/A"

    return f"""
    Published: {published}
    Base Score: {baseScore} ({baseSeverity})
    Vector: {vectorString}
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

def main(cve_ids, export_format=None, import_file=None, import_type=None, config_path=None, debug=False):
    global config
    config = load_config(config_path=config_path, debug=debug) if config_path else load_config(debug=debug)

    all_results = []
    if export_format:
        export_format = export_format.lower()
    if import_file and import_type:
        cve_ids = import_vulnerability_data(import_file, import_type)
        if not cve_ids:
            print("❌ No valid CVE IDs found in the provided file.")
            return
    if not cve_ids:
        print("❌ No CVE IDs provided. Please provide CVE IDs or an import file and type.")
        return

    for cve_id in cve_ids:
        cve_id = cve_id.upper()
        if not is_valid_cve_id(cve_id):
            print(f"❌ Invalid CVE ID format: {cve_id}. Please use the format CVE-YYYY-NNNNN.")
            continue

        print_cve_header(cve_id)

        cve_data = fetch_and_display_cve_data(cve_id)
        if not cve_data:
            continue

        epss_data = fetch_and_display_epss_score(cve_id)
        relevant_cisa_data = fetch_and_display_cisa_status(cve_id)
        public_exploits = fetch_and_display_public_exploits(cve_id)
        hackerone_data = fetch_and_display_hackerone_data(cve_id)

        cve_details = compile_cve_details(cve_id, cve_data, epss_data, relevant_cisa_data, public_exploits)
        risk_assessment = get_risk_assessment(cve_details, cve_data)
        display_ai_risk_assessment(cve_details, cve_data)

        priority = calculate_priority(
            cve_id, cve_data, epss_data, public_exploits["github_data"], relevant_cisa_data,
            public_exploits["vulncheck_data"], public_exploits["exploitdb_data"]
        )
        display_priority_rating(cve_id, priority)

        display_cve_references(cve_data)

        cve_result = {
            "CVE Data": cve_data,
            "EPSS Data": epss_data,
            "CISA Data": relevant_cisa_data,
            "Nuclei Data": public_exploits["nuclei_data"],
            "GitHub Data": public_exploits["github_data"],
            "VulnCheck Data": public_exploits["vulncheck_data"],
            "ExploitDB Data": public_exploits["exploitdb_data"],
            "PacketStorm Data": public_exploits["packetstorm_data"],
            "HackerOne Data": hackerone_data,
            "Priority": {"Priority": priority},
            "Risk Assessment": risk_assessment,
        }
        all_results.append(cve_result)

    if export_format == "json":
        export_to_json(all_results, cve_ids)
    elif export_format == "csv":
        export_to_csv(all_results, cve_ids)
    elif export_format == "html":
        export_to_html(all_results, cve_ids)


def cli():
    display_banner()
    parser = argparse.ArgumentParser(
        description="SploitScan: Retrieve and display vulnerability data as well as public exploits for given CVE ID(s)."
    )
    parser.add_argument(
        "cve_ids",
        type=str,
        nargs="*",
        default=[],
        help="Enter one or more CVE IDs to fetch data. Separate multiple CVE IDs with spaces. Format for each ID: CVE-YYYY-NNNNN. This argument is optional if an import file is provided using the -i option.",
    )
    parser.add_argument(
        "-e",
        "--export",
        choices=["json", "JSON", "csv", "CSV", "html", "HTML"],
        help="Optional: Export the results to a JSON, CSV, or HTML file. Specify the format: 'json', 'csv', or 'html'.",
    )
    parser.add_argument(
        "-t",
        "--type",
        choices=["nessus", "nexpose", "openvas", "docker"],
        help="Specify the type of the import file: 'nessus', 'nexpose', 'openvas' or 'docker'.",
    )
    parser.add_argument(
        "-i",
        "--import-file",
        type=str,
        help="Path to an import file from a vulnerability scanner. If used, CVE IDs can be omitted from the command line arguments.",
    )
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        help="Path to a custom config file.",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug output."
    )

    args = parser.parse_args()

    main(args.cve_ids, args.export, args.import_file, args.type, args.config, args.debug)

if __name__ == "__main__":
    cli()
