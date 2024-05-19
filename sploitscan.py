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
from jinja2 import Environment, FileSystemLoader


VERSION = "0.8"

BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
ENDC = "\033[0m"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
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


def fetch_nvd_data(cve_id):
    return fetch_json_data(NVD_API_URL.format(cve_id=cve_id))


def fetch_github_data(cve_id):
    url = f"{CVE_GITHUB_URL}/{cve_id[:4]}/{cve_id[4:7]}xx/{cve_id}.json"
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
    config = load_config()
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


def get_updated_cve_data(cve_id):
    nvd_data, nvd_error = fetch_nvd_data(cve_id)
    github_data, github_error = fetch_github_data(cve_id)
    if not nvd_data and not github_data:
        return {}, nvd_error or github_error

    if nvd_data and github_data:
        nvd_last_modified = nvd_data.get("vulnerabilities", [{}])[0].get(
            "lastModifiedDate", ""
        )
        github_last_modified = github_data.get("lastModifiedDate", "")
        return (
            nvd_data if nvd_last_modified > github_last_modified else github_data
        ), None
    return (nvd_data or github_data), None


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


def display_nvd_data(cve_data, error=None):
    def template(data):
        if not data or "vulnerabilities" not in data or not data["vulnerabilities"]:
            return ["└ ❌ No vulnerability data found."]

        cve_item = data["vulnerabilities"][0].get("cve", {})
        published = cve_item.get("published", "")
        if published:
            published_date = datetime.datetime.fromisoformat(published)
            published = published_date.strftime("%Y-%m-%d")
        description = next(
            (
                desc["value"]
                for desc in cve_item.get("descriptions", [])
                if desc["lang"] == "en"
            ),
            "No description available",
        ).replace("\n\n", " ")
        wrapped_description = textwrap.fill(
            description, width=100, subsequent_indent=" " * 15
        )
        metrics = cve_item.get("metrics", {})
        baseScore, baseSeverity, vectorString = "N/A", "N/A", "N/A"
        for version_prefix in ["cvssMetricV3", "cvssMetricV2"]:
            for key, value in metrics.items():
                if key.startswith(version_prefix):
                    cvss_data = value[0].get("cvssData", {})
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

    display_data("♾️ Exploit Prediction Score (EPSS)", epss_data, template, error)


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
                f"├ Date:        {created_at}\n└ URL:         {poc.get('html_url', 'N/A')}"
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
            entries.append(f"├ Date:        {item['date']}\n└ URL:         {url}")
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


def display_nvd_references(cve_data, error=None):
    def template(data):
        if not data or "vulnerabilities" not in data or not data["vulnerabilities"]:
            return ["└ ❌ No data found."]

        references = data["vulnerabilities"][0].get("cve", {}).get("references", [])
        return (
            [f"├ URL: {ref['url']}" for ref in references[:-1]]
            + [f"└ URL: {references[-1]['url']}"]
            if references
            else ["└ ❌ No further references found."]
        )

    display_data("📚 Further References", cve_data, template, error)


def calculate_priority(
    cve_id, nvd_data, epss_data, github_data, cisa_data, vulncheck_data, exploitdb_data
):
    cvss_score, epss_score = 0, 0
    try:
        cvss_score = float(
            nvd_data["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0][
                "cvssData"
            ]["baseScore"]
        )
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
    in_cisa_kev = any(
        vuln["cveID"] == cve_id for vuln in cisa_data.get("vulnerabilities", [])
    )
    has_public_exploits = (
        bool(github_data.get("pocs"))
        or bool(vulncheck_data.get("data"))
        or bool(exploitdb_data)
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
        display_data("⚠️ Patching Priority Rating", {"priority": priority}, template)


def load_config():
    default_config = {"vulncheck_api_key": None}
    config_paths = [
        "./config.json",
        os.path.expanduser("~/.sploitscan/config.json"),
        os.path.expanduser("~/.config/sploitscan/config.json"),
        "/etc/sploitscan/config.json",
    ]
    
    for config_path in config_paths:
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as file:
                    return json.load(file)
            except json.JSONDecodeError:
                print(f"⚠️ Error decoding JSON from the config file {config_path}, using default settings.")
            except Exception as e:
                print(f"⚠️ Unexpected error reading config file {config_path}: {e}, using default settings.")
    
    print("⚠️ Config file not found in any checked locations, using default settings.")
    return default_config


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
    cve_part = "_".join(cve_ids[:3]) + ("_and_more" if len(cve_ids) > 3 else "")
    return f"{timestamp}_{cve_part}_export.{extension}"


def datetimeformat(value, format="%Y-%m-%d"):
    return datetime.datetime.fromisoformat(value.rstrip("Z")).strftime(format)


def export_to_html(all_results, cve_ids):
    def template(data):
        template_paths = [
            "./templates",
            os.path.expanduser("~/.sploitscan/templates"),
            os.path.expanduser("~/.config/sploitscan/templates"),
            "/etc/sploitscan/templates",
        ]
        
        for path in template_paths:
            if os.path.exists(os.path.join(path, "report_template.html")):
                env = Environment(loader=FileSystemLoader(path))
                break
        else:
            print("❌ HTML template 'report_template.html' not found in any checked locations.")
            return ["❌ Error exporting to HTML: template not found"]
        
        env.filters["datetimeformat"] = datetimeformat
        template = env.get_template("report_template.html")
        filename = generate_filename(cve_ids, "html")
        output = template.render(cve_data=data)
        
        with open(filename, "w", encoding="utf-8") as file:
            file.write(output)
        
        return [f"└ Data exported to file: {filename}"]

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
        keys = data[0].keys()
        with open(filename, "w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=keys)
            writer.writeheader()
            for item in data:
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
    print(GREEN + "=" * len(header) + ENDC)
    print(GREEN + header + ENDC)
    print(GREEN + "=" * len(header) + ENDC + "\n")


def collect_cve_data(cve_id):
    cve_result = {"CVE ID": cve_id}
    print_cve_header(cve_id)

    nvd_data, nvd_error = fetch_nvd_data(cve_id)
    display_nvd_data(nvd_data, nvd_error)

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

    priority = calculate_priority(
        cve_id,
        nvd_data,
        epss_data,
        github_data,
        cisa_data,
        vulncheck_data,
        exploitdb_data,
    )
    display_priority_rating(cve_id, priority)

    display_nvd_references(nvd_data, nvd_error)

    cve_result.update(
        {
            "NVD Data": nvd_data,
            "EPSS Data": epss_data,
            "CISA Data": relevant_cisa_data,
            "Nuclei Data": nuclei_data,
            "GitHub Data": github_data,
            "VulnCheck Data": vulncheck_data,
            "ExploitDB Data": exploitdb_data,
            "PacketStorm Data": packetstorm_data,
            "Priority": {"Priority": priority},
        }
    )
    return cve_result


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
        cve_result = collect_cve_data(cve_id)
        all_results.append(cve_result)
    if export_format == "json":
        export_to_json(all_results, cve_ids)
    elif export_format == "csv":
        export_to_csv(all_results, cve_ids)
    elif export_format == "html":
        export_to_html(all_results, cve_ids)


if __name__ == "__main__":
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

    args = parser.parse_args()

    main(args.cve_ids, args.export, args.import_file, args.type)
