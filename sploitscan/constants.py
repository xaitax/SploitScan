"""
Centralized constants for SploitScan.
"""

from typing import Dict

# Version
VERSION: str = "0.14.0"

# ANSI Colors
BLUE: str = "\033[94m"
GREEN: str = "\033[92m"
YELLOW: str = "\033[93m"
ENDC: str = "\033[0m"

# URLs and API endpoints
CVE_GITHUB_URL: str = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
EPSS_API_URL: str = "https://api.first.org/data/v1/epss?cve={cve_id}"
CISA_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NUCLEI_URL: str = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
GITHUB_API_URL: str = "https://poc-in-github.motikan2010.net/api/v1/"
VULNCHECK_API_URL: str = "https://api.vulncheck.com/v3/index/vulncheck-kev"
EXPLOITDB_URL: str = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv?ref_type=heads"
HACKERONE_URL: str = "https://hackerone.com/graphql"

# Thresholds
CVSS_THRESHOLD: float = 6.0
EPSS_THRESHOLD: float = 0.2

# Priority color mapping
PRIORITY_COLORS: Dict[str, str] = {
    "A+": "\033[91m",
    "A": "\033[31m",
    "B": "\033[93m",
    "C": "\033[94m",
    "D": "\033[92m",
}
