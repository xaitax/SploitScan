#!/usr/bin/env python3

import requests
import argparse
import datetime
import textwrap
import json
import os
import csv
import re
import xml.etree.ElementTree as ET
from openai import OpenAI
from jinja2 import Environment, FileSystemLoader


VERSION = "0.10"

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
        return None, "API key for VulnCheck is not configured correctly."
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {vulncheck_api_key}",
    }
    return fetch_json_data(VULNCHECK_API_URL, params={"cve": cve_id}, headers=headers)


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
            published_date = datetime.datetime.fromisoformat(
                published.rstrip("Z"))
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
                f"└ EPSS Score:  {
                    float(epss_score) * 100:.2f}% Probability of exploitation."
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


def display_github_data(data, error=None):
    def template(data):
        entries = []
        for index, poc in enumerate(data.get("pocs", [])):
            created_at = poc.get("created_at", "N/A")
            if created_at != "N/A":
                created_date = datetime.datetime.fromisoformat(created_at)
                created_at = created_date.strftime("%Y-%m-%d")
            entries.append(
                f"├ Date:        {created_at}\n└ URL:         {
                    poc.get('html_url', 'N/A')}"
            )
            if index < len(data.get("pocs", [])) - 1:
                entries.append("|")
        return entries if entries else ["└ ❌ No data found."]

    display_data("💣 GitHub Exploits", data, template, error)


def display_vulncheck_data(vulncheck_data, error=None):
    def template(data):
        entries = []
        for index, item in enumerate(data.get("data", [])):
            for xdb_index, xdb in enumerate(item.get("vulncheck_xdb", [])):
                date_added = xdb.get("date_added", "N/A")
                if date_added != "N/A":
                    try:
                        date_added = datetime.datetime.fromisoformat(
                            date_added.rstrip("Z")
                        ).strftime("%Y-%m-%d")
                    except ValueError:
                        pass
                github_url = (
                    xdb.get("clone_ssh_url", "")
                    .replace("git@github.com:", "https://github.com/")
                    .replace(".git", "")
                )
                entries.append(
                    f"├ Date:        {date_added}\n└ URL:         {github_url}"
                )
                if (
                    index < len(data.get("data", [])) - 1
                    or xdb_index < len(item.get("vulncheck_xdb", [])) - 1
                ):
                    entries.append("|")
        return entries if entries else ["└ ❌ No data found."]

    display_data("💥 VulnCheck Exploits", vulncheck_data, template, error)


def display_exploitdb_data(exploitdb_data, cve_id, error=None):
    def template(data):
        entries = []
        for index, item in enumerate(
            sorted(data, key=lambda x: x["date"], reverse=True)
        ):
            url = f"https://www.exploit-db.com/exploits/{item['id']}"
            entries.append(f"├ Date:        {
                           item['date']}\n└ URL:         {url}")
            if index < len(data) - 1:
                entries.append("|")
        return entries if entries else ["└ ❌ No data found."]

    display_data("👾 Exploit-DB Exploits", exploitdb_data, template, error)


def display_packetstorm_data(packetstorm_data, error=None):
    def template(data):
        return [f"└ URL:         {data['packetstorm_url']}"]

    display_data("🎆 PacketStorm Exploits", packetstorm_data, template, error)


def display_nuclei_data(nuclei_data, error=None):
    def template(data):
        if not data or "file_path" not in data or not data["file_path"]:
            return ["└ ❌ No data found."]

        base_url = (
            "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/"
        )
        file_path = data["file_path"]
        full_url = f"{base_url}{file_path}"
        return [f"└ URL:         {full_url}"]

    display_data("⚛️ Nuclei Template", nuclei_data, template, error)


def display_hackerone_data(hackerone_data, error=None):
    def template(data):
        if not data or "data" not in data or "cve_entry" not in data["data"]:
            return ["└ ❌ No data found."]

        cve_entry = data["data"]["cve_entry"]
        if not cve_entry:
            return ["└ ❌ No data found."]
        
        rank = cve_entry.get("rank", "N/A")
        reports_submitted_count = cve_entry.get("reports_submitted_count", "N/A")
        return [
            f"├ Rank:        {rank}",
            f"└ Reports:     {reports_submitted_count}",
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


def load_config(debug=False):
    default_config = {"vulncheck_api_key": None, "openai_api_key": None}
    base_path = os.path.dirname(os.path.abspath(__file__))
    config_paths = [
        os.path.join(base_path, "config.json"),
        os.path.expanduser("~/.sploitscan/config.json"),
        os.path.expanduser("~/.config/sploitscan/config.json"),
        "/etc/sploitscan/config.json",
    ]

    for config_path in config_paths:
        if os.path.exists(config_path):
            try:
                if debug:
                    print(f"⚠️ Attempting to load config file from: {
                          config_path}")
                with open(config_path, "r", encoding="utf-8") as file:
                    config = json.load(file)
                    if debug:
                        print(f"⚠️ Successfully loaded config file: {
                              config_path}")
                    return config
            except json.JSONDecodeError as e:
                print(f"⚠️ Error decoding JSON from the config file {
                      config_path}: {e}")
            except Exception as e:
                print(f"⚠️ Unexpected error reading config file {
                      config_path}: {e}")

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
    assessment = get_risk_assessment(cve_details, cve_data)

    print("┌───[ 🤖 AI-Powered Risk Assessment ]")
    print("|")

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
        print(f"❌ An unexpected error occurred while processing '{
              file_path}': {e}")
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
            metrics = result.get("CVE Data", {}).get(
                "containers", {}).get("cna", {}).get("metrics", [])
            for metric in metrics:
                if "cvssV3_1" not in metric and "cvssV3" not in metric:
                    metric["cvssV3_1"] = {
                        "baseScore": "N/A", "baseSeverity": "N/A", "vectorString": "N/A"}
        return data

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


def main(cve_ids, export_format=None, import_file=None, import_type=None):
    all_results = []
    if export_format:
        export_format = export_format.lower()
    if import_file and import_type:
        cve_ids = import_vulnerability_data(import_file, import_type)
        if not cve_ids:
            print("❌ No valid CVE IDs found in the provided file.")
            return
    if not cve_ids:
        print(
            "❌ No CVE IDs provided. Please provide CVE IDs or an import file and type."
        )
        return
    for cve_id in cve_ids:
        cve_id = cve_id.upper()
        if not is_valid_cve_id(cve_id):
            print(
                f"❌ Invalid CVE ID format: {cve_id}. Please use the format CVE-YYYY-NNNNN."
            )
            continue

        cve_result = {"CVE ID": cve_id}
        print_cve_header(cve_id)

        cve_data, cve_error = fetch_github_cve_data(cve_id)
        display_cve_data(cve_data, cve_error)

        if not cve_data:
            continue

        epss_data, epss_error = fetch_epss_score(cve_id)
        display_epss_score(epss_data, epss_error)

        cisa_data, cisa_error = fetch_cisa_data()
        display_cisa_status(cve_id, cisa_data, cisa_error)

        relevant_cisa_data = next(
            (
                item
                for item in cisa_data.get("vulnerabilities", [])
                if item["cveID"] == cve_id
            ),
            None,
        )

        github_data, github_error = fetch_json_data(
            GITHUB_API_URL, params={"cve_id": cve_id}
        )
        display_github_data(github_data, github_error)

        vulncheck_data, vulncheck_error = fetch_vulncheck_data(cve_id)
        display_vulncheck_data(vulncheck_data, vulncheck_error)

        exploitdb_data, exploitdb_error = fetch_exploitdb_data(cve_id)
        display_exploitdb_data(exploitdb_data, cve_id, exploitdb_error)

        packetstorm_data, packetstorm_error = fetch_packetstorm_data(cve_id)
        display_packetstorm_data(packetstorm_data, packetstorm_error)

        nuclei_data, nuclei_error = fetch_nuclei_data(cve_id)
        display_nuclei_data(nuclei_data, nuclei_error)

        hackerone_data, hackerone_error = fetch_hackerone_cve_details(cve_id)
        display_hackerone_data(hackerone_data, hackerone_error)

        published = cve_data["cveMetadata"].get("datePublished", "N/A")
        if published != "N/A":
            published = datetime.datetime.fromisoformat(published.rstrip("Z")).strftime(
                "%Y-%m-%d"
            )

        description = (
            next(
                (
                    desc["value"]
                    for desc in cve_data["containers"]["cna"].get("descriptions", [])
                    if desc["lang"] == "en"
                ),
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

        epss_score = (
            epss_data["data"][0].get("epss", "N/A")
            if epss_data and "data" in epss_data
            else "N/A"
        )

        cisa_status = relevant_cisa_data["cisa_status"] if relevant_cisa_data else "N/A"
        ransomware_use = (
            relevant_cisa_data["ransomware_use"] if relevant_cisa_data else "N/A"
        )

        github_exploits = (
            "\n".join(
                [
                    f"{poc['created_at']}: {poc['html_url']}"
                    for poc in github_data.get("pocs", [])
                ]
            )
            if github_data
            else "N/A"
        )

        vulncheck_exploits = (
            "\n".join(
                [
                    f"{xdb['date_added']}: {xdb['clone_ssh_url'].replace('git@github.com:', 'https://github.com/').replace('.git', '')}"
                    for item in vulncheck_data.get("data", [])
                    for xdb in item.get("vulncheck_xdb", [])
                ]
            )
            if vulncheck_data
            else "N/A"
        )

        packetstorm_url = packetstorm_data.get("packetstorm_url", "N/A")

        nuclei_url = (
            f"https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/{nuclei_data['file_path']}"
            if nuclei_data and "file_path" in nuclei_data
            else "N/A"
        )

        references = (
            "\n".join(
                [
                    ref["url"]
                    for ref in cve_data["containers"]["cna"].get("references", [])
                ]
            )
            if cve_data
            else "N/A"
        )

        cve_details = f"""
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
        risk_assessment = get_risk_assessment(cve_details, cve_data)
        display_ai_risk_assessment(cve_details, cve_data)

        priority = calculate_priority(
            cve_id,
            cve_data,
            epss_data,
            github_data,
            cisa_data,
            vulncheck_data,
            exploitdb_data,
        )
        display_priority_rating(cve_id, priority)

        display_cve_references(cve_data, cve_error)

        cve_result.update(
            {
                "CVE Data": cve_data,
                "EPSS Data": epss_data,
                "CISA Data": relevant_cisa_data,
                "Nuclei Data": nuclei_data,
                "GitHub Data": github_data,
                "VulnCheck Data": vulncheck_data,
                "ExploitDB Data": exploitdb_data,
                "PacketStorm Data": packetstorm_data,
                "HackerOne Data": hackerone_data,
                "Priority": {"Priority": priority},
                "Risk Assessment": risk_assessment,
            }
        )
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
        help="Enter one or more CVE IDs to fetch data. Separate multiple CVE IDs with spaces. Format for each ID: CVE-YYYY-NNNNN. This argument is optional if an import file is provided using the -n option.",
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
        "-d",
        "--debug",
        action="store_true",
        help="Enable debug output."
    )

    args = parser.parse_args()

    global config
    config = load_config(args.debug)

    main(args.cve_ids, args.export, args.import_file, args.type)


if __name__ == "__main__":
    cli()
