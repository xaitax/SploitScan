import requests
import argparse
import datetime
import re
from tabulate import tabulate

BLUE = "\033[94m"
ENDC = "\033[0m"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
EPSS_API_URL = "https://api.first.org/data/v1/epss?cve={cve_id}"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
POC_API_URL = "https://poc-in-github.motikan2010.net/api/v1/"


def fetch_nvd_data(cve_id):
    nvd_url = NVD_API_URL.format(cve_id=cve_id)
    try:
        response = requests.get(nvd_url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[❌] Error fetching data from NVD: {e}")


def display_nvd_data(cve_data):
    if (
        cve_data
        and "vulnerabilities" in cve_data
        and len(cve_data["vulnerabilities"]) > 0
    ):
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

        metrics = cve_item.get("metrics", {}).get("cvssMetricV31", [])
        baseScore = baseSeverity = "N/A"
        if metrics:
            cvss_data = metrics[0].get("cvssData", {})
            baseScore = cvss_data.get("baseScore", "N/A")
            baseSeverity = cvss_data.get("baseSeverity", "N/A")

        label_width = max(
            len("Description:"),
            len("Published:"),
            len("Base Score:"),
            len("Base Severity:"),
        )
        description_label = "Description:".ljust(label_width)
        published_label = "Published:".ljust(label_width)
        base_score_label = "Base Score:".ljust(label_width)
        base_severity_label = "Base Severity:".ljust(label_width)

        print(
            f"\n{description_label} {description}\n{published_label} {published}\n{base_score_label} {baseScore}\n{base_severity_label} {baseSeverity}\n"
        )
    else:
        print("\n[❌] No NVD data found for this CVE ID.\n")


def fetch_epss_score(cve_id):
    epss_url = EPSS_API_URL.format(cve_id=cve_id)
    try:
        response = requests.get(epss_url)
        response.raise_for_status()
        epss_data = response.json()
        if epss_data and "data" in epss_data and len(epss_data["data"]) > 0:
            epss_score = epss_data["data"][0].get("epss", "N/A")
            return float(epss_score)
        return "N/A"
    except requests.exceptions.RequestException as e:
        print(f"[❌] Error fetching EPSS data: {e}")
        return "N/A"


def display_epss_score(epss_score):
    if epss_score != "N/A":
        print(
            f"EPSS Score:    {float(epss_score) * 100:.2f}% Probability of exploitation in the wild (following publication).\n"
        )
    else:
        print("[❌] No EPSS data found for this CVE ID.\n")


def fetch_cisa_data():
    try:
        response = requests.get(CISA_URL)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[❌] Error fetching data from CISA: {e}")


def display_cisa_status(cve_id, cisa_data):
    cisa_status = "No"
    if cisa_data and "vulnerabilities" in cisa_data:
        for vulnerability in cisa_data["vulnerabilities"]:
            if vulnerability["cveID"] == cve_id:
                cisa_status = "Yes"
                break

    print(f"CISA Known Exploited Vulnerabilities Listing: {cisa_status}")


def fetch_poc_data(base_url, params=None):
    try:
        response = requests.get(base_url, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[❌] An error occurred fetching PoC data: {e}")


def display_poc_data(data):
    headers = ["Name", "Author", "Stars", "Date", "URL"]
    table = []

    if "pocs" in data and len(data["pocs"]) > 0:
        for poc in data["pocs"]:
            created_at = poc.get("created_at", "N/A")
            if created_at != "N/A":
                created_date = datetime.datetime.fromisoformat(created_at)
                created_at = created_date.strftime("%Y-%m-%d")

            row = [
                poc.get("name", "N/A"),
                poc.get("owner", "N/A"),
                poc.get("stargazers_count", 0),
                created_at,
                poc.get("html_url", "N/A"),
            ]
            table.append(row)

        print(tabulate(table, headers=headers, tablefmt="fancy_grid"))
    else:
        print("No PoC data found.")


def is_valid_cve_id(cve_id):
    return re.match(r"CVE-\d{4}-\d{4,7}$", cve_id) is not None


def display_banner():
    banner = """
███████╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██████╔╝██║     ██║   ██║██║   ██║   ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║     ███████╗╚██████╔╝██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
"""
    print(BLUE + banner + ENDC)
    print("Alexander Hagenah / @xaitax / ah@primepage.de\n")


def main(cve_id):
    if not cve_id:
        print(
            "[❌] No CVE ID provided. Please provide a CVE ID in the format CVE-YYYY-NNNNN."
        )
        return

    if not is_valid_cve_id(cve_id):
        print(
            "[❌] Invalid CVE ID format. Please provide a CVE ID in the format CVE-YYYY-NNNNN."
        )
        return

    print(BLUE + f"🔍 Fetching vulnerability information for {cve_id}." + ENDC)
    nvd_data = fetch_nvd_data(cve_id)
    display_nvd_data(nvd_data)

    print(BLUE + f"💥 Fetching Exploit Prediction Score (EPSS) for {cve_id}.\n" + ENDC)
    epss_score = fetch_epss_score(cve_id)
    display_epss_score(epss_score)

    print(BLUE + f"🛡️ Fetching CISA Catalog of Known Exploited Vulnerabilities for {cve_id}.\n" + ENDC)
    cisa_data = fetch_cisa_data()
    display_cisa_status(cve_id, cisa_data)

    print(BLUE + f"\n💣 Fetching public exploits / PoC for {cve_id}.\n" + ENDC)
    poc_data = fetch_poc_data(
        POC_API_URL, params={"cve_id": cve_id, "sort": "stargazers_count"}
    )
    display_poc_data(poc_data)


if __name__ == "__main__":
    display_banner()
    parser = argparse.ArgumentParser(
        description="SploitScan: Fetch and display data from NVD and public exploits for a given CVE ID."
    )
    parser.add_argument(
        "cve_id",
        type=str,
        nargs="?",
        default="",
        help="The CVE ID for which to fetch data. Format: CVE-YYYY-NNNNN (Example: CVE-2023-23397)",
    )
    args = parser.parse_args()

    main(args.cve_id)
