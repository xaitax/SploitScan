# SploitScan

## 📜 Description

SploitScan is a powerful and user-friendly tool designed to streamline the process of identifying exploits for known vulnerabilities and their respective exploitation probability. Empowering cybersecurity professionals with the capability to swiftly identify and apply known and test exploits. It's particularly valuable for professionals seeking to enhance their security measures or develop robust detection strategies against emerging threats.

## 🌟 Features

- **CVE Information Retrieval**: Fetches CVE details from the National Vulnerability Database.
- **EPSS Integration**: Includes Exploit Prediction Scoring System (EPSS) data, offering a probability score for the likelihood of CVE exploitation, aiding in prioritization.
- **Public Exploits Aggregation**: Gathers publicly available exploits, enhancing the understanding of vulnerabilities.
- **CISA KEV**: Shows if the CVE has been listed in the Known Exploited Vulnerabilities (KEV) of CISA.
- **Patching Priority System**: Evaluates and assigns a priority rating for patching based on various factors including public exploits availability.
- **Multi-CVE Support and Export Options**: Supports multiple CVEs in a single run and allows exporting the results to JSON and CSV formats.
- **User-Friendly Interface**: Easy to use, providing clear and concise information.
- **Comprehensive Security Tool**: Ideal for quick security assessments and staying informed about recent vulnerabilities.

## 💣 Supported Exploit Databases

- **[GitHub](https://poc-in-github.motikan2010.net/)**
- **[ExploitDB](https://www.exploit-db.com/)**
- **[VulnCheck](https://vulncheck.com/)** (requires a VulnCheck API key)

## 🚀 Usage

![image](https://github.com/xaitax/SploitScan/assets/5014849/fc594ec8-8c91-4797-bb00-3c8884871b5c)

<hr>

**Regular**:

```bash
python sploitscan.py CVE-YYYY-NNNNN
```

**Enter one or more CVE IDs to fetch data. Separate multiple CVE IDs with spaces.**

```bash
python sploitscan.py CVE-YYYY-NNNNN CVE-YYYY-NNNNN
```

**Optional: Export the results to a JSON or CSV file. Specify the format: 'json' or 'csv'.**

```bash
python sploitscan.py CVE-YYYY-NNNNN -e JSON
```

## 🛡️ Patching Prioritization System

The Patching Prioritization System in SploitScan provides a strategic approach to prioritizing security patches based on the severity and exploitability of vulnerabilities. It's influenced by the model from [CVE Prioritizer](https://github.com/TURROKS/CVE_Prioritizer), with enhancements for handling publicly available exploits. Here's how it works:

- A+ Priority: Assigned to CVEs listed in CISA's KEV or those with publicly available exploits. This reflects the highest risk and urgency for patching.
- A to D Priority: Based on a combination of CVSS scores and EPSS probability percentages. The decision matrix is as follows:
  - A: CVSS score >= 6.0 and EPSS score >= 0.2. High severity with a significant probability of exploitation.
  - B: CVSS score >= 6.0 but EPSS score < 0.2. High severity but lower probability of exploitation.
  - C: CVSS score < 6.0 and EPSS score >= 0.2. Lower severity but higher probability of exploitation.
  - D: CVSS score < 6.0 and EPSS score < 0.2. Lower severity and lower probability of exploitation.

This system assists users in making informed decisions on which vulnerabilities to patch first, considering both their potential impact and the likelihood of exploitation. Thresholds can be changed to your business needs.

## 📆 Changelog

### [02. March 2024] - Version 0.5
- **ExploitDB Integration**: Added support for fetching exploit data from ExploitDB.
- **CVSS Enhancements**: Added support for CVSS 2 and CVSS 3.x
- **Code fixes**

### [28. February 2024] - Version 0.4
- **VulnCheck Integration**: Added support for fetching exploit data from VulnCheck, enhancing the exploit information available.
- **API Key Configuration**: Introduced the requirement for a VulnCheck API key, specified in config.json.
- **Requirements satisfied for Debian Integration**

### [17. February 2024] - Version 0.3

- **Additional Information**: Added further information such as references & vector string
- **Removed**: Star count in publicly available exploits

### [15. January 2024] - Version 0.2

- **Multiple CVE Support**: Now capable of handling multiple CVE IDs in a single execution.
- **JSON and CSV Export**: Added functionality to export results to JSON and CSV files.
- **Enhanced CVE Display**: Improved visual differentiation and information layout for each CVE.
- **Patching Priority System**: Introduced a priority rating system for patching, influenced by various factors including the availability of public exploits.

### [13th January 2024] - Version 0.1

- Initial release of SploitScan.

## 🫱🏼‍🫲🏽 Contributing
Contributions are welcome. Please feel free to fork, modify, and make pull requests or report issues.

- [Nilsonfsilva](https://github.com/Nilsonfsilva) for support on Debian packaging
- [bcoles](https://github.com/bcoles) for bugfixes.
- [Romullo](https://github.com/Romullo) for ideas & suggestions.

## 📌 Author

**Alexander Hagenah**
- [URL](https://primepage.de)
- [Twitter](https://twitter.com/xaitax)

## 👏 Credits

- [NIST NVD](https://nvd.nist.gov/developers/vulnerabilities)
- [FIRST EPSS](https://www.first.org/epss/api)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [VulnCheck](https://vulncheck.com/)
- [ExploitDB](https://www.exploit-db.com/)
- [nomi-sec PoC-in-GitHub API](https://poc-in-github.motikan2010.net/)
