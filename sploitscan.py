#!/usr/bin/env python3

import requests
import argparse
import datetime
import json
import os
import csv
import re
import xml.etree.ElementTree as ET
from tabulate import tabulate

VERSION = "0.6.1"

BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
ENDC = "\033[0m"

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
EPSS_API_URL = "https://api.first.org/data/v1/epss?cve={cve_id}"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_API_URL = "https://poc-in-github.motikan2010.net/api/v1/"
VULNCHECK_API_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
EXPLOITDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv?ref_type=heads"

CVSS_THRESHOLD = 6.0
EPSS_THRESHOLD = 0.2

PRIORITY_COLORS = {
    "A+": "\033[91m",
    "A": "\033[31m",
    "B": "\033[93m",
    "C": "\033[94m",
    "D": "\033[92m",
}


def fetch_nvd_data(cve_id):
    nvd_url = NVD_API_URL.format(cve_id=cve_id)
    try:
        response = requests.get(nvd_url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching data from NVD: {e}")
        return {}


def display_nvd_data(cve_data):
    if cve_data and "vulnerabilities" in cve_data and cve_data["vulnerabilities"]:

        cve_item = cve_data["vulnerabilities"][0]["cve"]
        published = cve_item.get("published", "")
        if published:
            published_date = datetime.datetime.fromisoformat(published)
            published = published_date.strftime("%Y-%m-%d")

        descriptions = cve_item.get("descriptions", [])
        description = next(
            (desc["value"] for desc in descriptions if desc["lang"] == "en"),
            "No description available",
        )
        description = description.replace("\n\n", "")

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

        labels = [
            "Description:",
            "Published:",
            "Base Score:",
            "Base Severity:",
            "Vector String:",
        ]
        label_width = max(map(len, labels))
        formatted_labels = [label.ljust(label_width) for label in labels]

        print(
            f"\n{description}\n\n"
            f"{formatted_labels[1]} {published}\n"
            f"{formatted_labels[2]} {baseScore}\n"
            f"{formatted_labels[3]} {baseSeverity}\n"
            f"{formatted_labels[4]} {vectorString}\n"
        )
    else:
        print("\n❌ No NVD data found for this CVE ID.\n")


def fetch_epss_score(cve_id):
    epss_url = EPSS_API_URL.format(cve_id=cve_id)
    try:
        response = requests.get(epss_url)
        response.raise_for_status()
        epss_data = response.json()
        return epss_data
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching EPSS data: {e}")
        return None


def display_epss_score(epss_data):
    if epss_data and "data" in epss_data and len(epss_data["data"]) > 0:
        epss_score = epss_data["data"][0].get("epss", "N/A")
        if epss_score != "N/A":
            print(
                f"EPSS Score:    {float(epss_score) * 100:.2f}% Probability of exploitation.\n"
            )
    else:
        print("❌ No EPSS data found for this CVE ID.\n")


def fetch_cisa_data():
    try:
        response = requests.get(CISA_URL)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching data from CISA: {e}")


def display_cisa_status(cve_id, cisa_data):
    cisa_status = "No"
    ransomware_use = "Unknown"
    if cisa_data and "vulnerabilities" in cisa_data:
        for vulnerability in cisa_data["vulnerabilities"]:
            if vulnerability["cveID"] == cve_id:
                cisa_status = "Yes"
                ransomware_use = vulnerability.get(
                    "knownRansomwareCampaignUse", "Unknown"
                )
                break

    print(f"CISA KEV Listing: {cisa_status}")
    if cisa_status == "Yes":
        print(f"Known Ransomware: {ransomware_use}")


def fetch_github_data(base_url, params=None):
    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ An error occurred fetching PoC data: {e}")


def display_github_data(data):
    headers = ["Name", "Date", "URL"]
    table = []

    if "pocs" in data and len(data["pocs"]) > 0:
        for poc in data["pocs"]:
            name = poc.get("name", "N/A")
            if len(name) > 45:
                name = name[:45] + "[...]"
            created_at = poc.get("created_at", "N/A")
            if created_at != "N/A":
                created_date = datetime.datetime.fromisoformat(created_at)
                created_at = created_date.strftime("%Y-%m-%d")

            row = [
                name,
                created_at,
                poc.get("html_url", "N/A"),
            ]
            table.append(row)

        table.sort(key=lambda x: x[1], reverse=True)
        print(tabulate(table, headers=headers, tablefmt="fancy_grid") + "\n")
    else:
        print("No exploit data found.\n")


def load_config(config_file="config.json"):
    default_config = {"vulncheck_api_key": None}
    if not os.path.exists(config_file):
        print("⚠️ Config file not found, using default settings.")
        return default_config

    try:
        with open(config_file, "r") as file:
            config = json.load(file)
    except json.JSONDecodeError:
        print("⚠️ Error decoding JSON from the config file, using default settings.")
        return default_config
    except Exception as e:
        print(f"⚠️ Unexpected error reading config file: {e}, using default settings.")
        return default_config

    return config


def fetch_vulncheck_data(cve_id):
    config = load_config()
    vulncheck_api_key = config.get("vulncheck_api_key")
    if not vulncheck_api_key:
        print("❌ API key for VulnCheck is not configured correctly.")
        return None

    url = VULNCHECK_API_URL
    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {vulncheck_api_key}",
    }
    params = {"cve": cve_id}

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching data from VulnCheck: {e}")
        return None


def display_vulncheck_data(vulncheck_data):
    table = []

    if vulncheck_data and "data" in vulncheck_data:
        for item in vulncheck_data["data"]:
            if "vulncheck_xdb" in item:
                for xdb in item["vulncheck_xdb"]:
                    xdb_id = xdb.get("xdb_id", "N/A")

                    date_added = xdb.get("date_added", "N/A")
                    if date_added != "N/A":
                        try:
                            date_added = datetime.datetime.fromisoformat(
                                date_added.rstrip("Z")
                            ).strftime("%Y-%m-%d")
                        except ValueError:
                            pass

                    clone_ssh_url = xdb.get("clone_ssh_url", "")
                    github_url = clone_ssh_url.replace(
                        "git@github.com:", "https://github.com/"
                    ).replace(".git", "")

                    table.append([xdb_id, date_added, github_url])

        table.sort(key=lambda x: x[1], reverse=True)

    if table:
        print(tabulate(table, headers=["ID", "Date", "URL"], tablefmt="fancy_grid"))
    else:
        print("No exploit data found.")


def fetch_exploitdb_data(cve_id):
    exploitdb_url = EXPLOITDB_URL
    try:
        response = requests.get(exploitdb_url)
        response.raise_for_status()

        decoded_content = response.content.decode("utf-8")
        csv_reader = csv.reader(decoded_content.splitlines(), delimiter=",")
        header = next(csv_reader)
        codes_index = header.index("codes")
        exploitdb_data = []
        for row in csv_reader:
            codes = row[codes_index].split(";")
            if cve_id in codes:
                exploitdb_data.append(
                    {
                        "id": row[0],
                        "date": row[3],
                    }
                )
        return exploitdb_data
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching data from ExploitDB.")
        return []


def display_exploitdb_data(exploitdb_data, cve_id):
    headers = ["ID", "Date", "URL"]
    table = []

    for data in exploitdb_data:
        exploit_id = data.get("id", "N/A")
        date_published = data.get("date", "N/A")
        url = f"https://www.exploit-db.com/exploits/{exploit_id}"

        table.append([exploit_id, date_published, url])

    if table:
        print(tabulate(table, headers=headers, tablefmt="fancy_grid"))
    else:
        print("No exploit data found.")


def display_nvd_references(cve_data):
    if (
        cve_data
        and "vulnerabilities" in cve_data
        and len(cve_data["vulnerabilities"]) > 0
    ):
        references = cve_data["vulnerabilities"][0]["cve"].get("references", [])
        if references:
            for reference in references:
                print(f"URL: {reference['url']}")
            print()
        else:
            print("❌ No further references found.\n")
    else:
        print("❌ No NVD data found to extract references from.\n")


def calculate_priority(
    cve_id, nvd_data, epss_data, github_data, cisa_data, vulncheck_data, exploitdb_data
):
    cvss_score = 0
    epss_score = 0

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
            if epss_data and "data" in epss_data and epss_data["data"]
            else 0
        )
    except (KeyError, IndexError, TypeError):
        pass

    in_cisa_kev = any(
        vuln["cveID"] == cve_id for vuln in cisa_data.get("vulnerabilities", [])
    )

    has_public_exploits = (
        len(github_data.get("pocs", [])) > 0
        or len(vulncheck_data.get("data", [])) > 0
        or len(exploitdb_data) > 0
    )

    if in_cisa_kev or has_public_exploits:
        priority = "A+"
    elif cvss_score >= CVSS_THRESHOLD and epss_score >= EPSS_THRESHOLD:
        priority = "A"
    elif cvss_score >= CVSS_THRESHOLD and epss_score < EPSS_THRESHOLD:
        priority = "B"
    elif cvss_score < CVSS_THRESHOLD and epss_score >= EPSS_THRESHOLD:
        priority = "C"
    else:
        priority = "D"

    return priority


def import_vulnerability_data(file_path, file_type):
    if not os.path.exists(file_path):
        print(f"❌ Error: The file '{file_path}' does not exist.")
        return []

    if file_type == "nessus":
        return import_nessus(file_path)
    elif file_type == "nexpose":
        return import_nexpose(file_path)
    elif file_type == "openvas":
        return import_openvas(file_path)
    elif file_type == "docker":
        return import_docker(file_path)
    else:
        print(f"❌ Unsupported file type: {file_type}")
        return []


def import_nessus(file_path):
    cve_ids = []
    if not os.path.exists(file_path):
        print(f"❌ Error: The file '{file_path}' does not exist.")
        return cve_ids

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        for report_item in root.findall(".//ReportItem"):
            cves = report_item.findall("cve")
            for cve in cves:
                cve_id = cve.text.strip()
                if is_valid_cve_id(cve_id):
                    cve_ids.append(cve_id)
        unique_cve_ids = list(set(cve_ids))

        print(
            YELLOW
            + f"📥 Successfully imported {len(unique_cve_ids)} CVE(s) from '{file_path}'.\n"
        )
        return unique_cve_ids
    except ET.ParseError as e:
        print(f"❌ Error parsing the Nessus file '{file_path}': {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred while processing '{file_path}': {e}")
    return cve_ids


def import_nexpose(file_path):
    cve_ids = []
    if not os.path.exists(file_path):
        print(f"❌ Error: The file '{file_path}' does not exist.")
        return cve_ids

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        url_links = root.findall(".//URLLink")
        for link in url_links:
            link_title = link.get("LinkTitle")
            if link_title and link_title.startswith("CVE-"):
                cve_ids.append(link_title)

        unique_cve_ids = list(set(cve_ids))
        print(
            YELLOW
            + f"📥 Successfully imported {len(unique_cve_ids)} CVE(s) from '{file_path}'.\n"
        )
        return unique_cve_ids
    except ET.ParseError as e:
        print(f"❌ Error parsing the Nexpose file '{file_path}': {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred while processing '{file_path}': {e}")

    return cve_ids


def import_openvas(file_path):
    cve_ids = []

    if not os.path.exists(file_path):
        print("❌ Error: The file does not exist.")
        return cve_ids

    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        cve_elements = root.findall(".//cve")
        for cve_element in cve_elements:
            cve_text = cve_element.text.strip()
            if cve_text and cve_text != "NOCVE":
                split_cves = cve_text.split(",")
                for cve in split_cves:
                    cve = cve.strip()
                    if cve.startswith("CVE-"):
                        cve_ids.append(cve)

        unique_cve_ids = list(set(cve_ids))
        print(f"📥 Successfully imported {len(unique_cve_ids)} CVE(s) from '{file_path}'.\n")
        return unique_cve_ids
    except ET.ParseError as e:
        print(f"❌ Error parsing the file: {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")

    return cve_ids

def import_docker(file_path):
    cve_ids = []

    if not os.path.exists(file_path):
        print(f"❌ Error: The file '{file_path}' does not exist.")
        return cve_ids

    try:
        with open(file_path, 'r') as file:
            data = json.load(file)

        runs = data.get('runs', [])
        for run in runs:
            rules = run.get('tool', {}).get('driver', {}).get('rules', [])
            for rule in rules:
                cve_id = rule.get('id', '')
                if cve_id.startswith('CVE-'):
                    cve_ids.append(cve_id)

        unique_cve_ids = list(set(cve_ids))
        print(f"📥 Successfully imported {len(unique_cve_ids)} CVE(s) from '{file_path}'.\n")
        return unique_cve_ids
    except json.JSONDecodeError as e:
        print(f"❌ Error parsing the Docker Scout file '{file_path}': {e}")
    except Exception as e:
        print(f"❌ An unexpected error occurred while processing '{file_path}': {e}")

    return cve_ids

def is_valid_cve_id(cve_id):
    return re.match(r"CVE-\d{4}-\d{4,7}$", cve_id) is not None


def generate_filename(cve_ids, extension):
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    if len(cve_ids) > 3:
        cve_part = "_".join(cve_ids[:3]) + "_and_more"
    else:
        cve_part = "_".join(cve_ids)

    filename = f"{timestamp}_{cve_part}_export.{extension}"
    return filename


def export_to_json(all_results, cve_ids):
    if not all_results:
        print("❌ No data to export.")
        return

    filename = generate_filename(cve_ids, "json")
    with open(filename, "w") as file:
        json.dump(all_results, file, indent=4)
    print(BLUE + f"✅ Data exported to JSON file: {filename}\n" + ENDC)


def export_to_csv(all_results, cve_ids):
    if not all_results:
        print("❌ No data to export.")
        return

    filename = generate_filename(cve_ids, "csv")
    keys = all_results[0].keys()
    with open(filename, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=keys)
        writer.writeheader()
        for data in all_results:
            writer.writerow(data)
    print(BLUE + f"✅ Data exported to CSV file: {filename}\n" + ENDC)


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


def main(cve_ids, export_format=None, import_file=None, import_type=None):
    config = load_config()
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


def print_cve_header(cve_id):
    header = f" CVE ID: {cve_id} "
    print(GREEN + "=" * len(header) + ENDC)
    print(GREEN + header + ENDC)
    print(GREEN + "=" * len(header) + ENDC + "\n")


def collect_cve_data(cve_id):
    cve_result = {"CVE ID": cve_id}
    print_cve_header(cve_id)

    print(BLUE + f"🔍 Fetching vulnerability information:" + ENDC)
    nvd_data = fetch_nvd_data(cve_id)
    display_nvd_data(nvd_data)

    print(BLUE + f"♾️ Fetching Exploit Prediction Score (EPSS):\n" + ENDC)
    epss_data = fetch_epss_score(cve_id)
    display_epss_score(epss_data)

    print(BLUE + f"🛡️ Fetching CISA KEV Catalog:\n" + ENDC)
    cisa_data = fetch_cisa_data()
    display_cisa_status(cve_id, cisa_data)

    print(BLUE + f"\n💣 Fetching GitHub exploits / PoC: \n" + ENDC)
    github_data = fetch_github_data(
        GITHUB_API_URL, params={"cve_id": cve_id, "sort": "stargazers_count"}
    )
    display_github_data(github_data)

    print(BLUE + f"💥 Fetching VulnCheck exploits / PoC: \n" + ENDC)
    vulncheck_data = fetch_vulncheck_data(cve_id)
    display_vulncheck_data(vulncheck_data)

    print(BLUE + f"\n👾 Fetching ExploitDB exploits / PoC: \n" + ENDC)
    exploitdb_data = fetch_exploitdb_data(cve_id)
    display_exploitdb_data(exploitdb_data, cve_id)

    print(BLUE + f"\n📚 Further references: \n" + ENDC)
    display_nvd_references(nvd_data)

    priority = calculate_priority(
        cve_id,
        nvd_data,
        epss_data,
        github_data,
        cisa_data,
        vulncheck_data,
        exploitdb_data,
    )
    priority_color = PRIORITY_COLORS.get(priority, ENDC)
    print(BLUE + f"⚠️ Patching Priority Rating: {priority_color}{priority}{ENDC}\n")

    relevant_cisa_data = next(
        (
            item
            for item in cisa_data.get("vulnerabilities", [])
            if item["cveID"] == cve_id
        ),
        None,
    )

    cve_result.update(
        {
            "NVD Data": nvd_data,
            "EPSS Data": epss_data,
            "CISA Data": relevant_cisa_data,
            "GitHub Data": github_data,
            "VulnCheck Data": vulncheck_data,
            "ExploitDB Data": exploitdb_data,
            "Priority": {"Priority": priority},
        }
    )
    return cve_result


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
        choices=["json", "JSON", "csv", "CSV"],
        help="Optional: Export the results to a JSON or CSV file. Specify the format: 'json' or 'csv'.",
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
