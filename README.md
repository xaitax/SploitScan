# SploitScan

![sploitscan_v0 8](https://github.com/xaitax/SploitScan/assets/5014849/ec5c1a79-cee8-4b06-9ea5-fd063651c8fc)

## 📜 Description

SploitScan is a powerful and user-friendly tool designed to streamline the process of identifying exploits for known vulnerabilities and their respective exploitation probability. Empowering cybersecurity professionals with the capability to swiftly identify and apply known and test exploits. It's particularly valuable for professionals seeking to enhance their security measures or develop robust detection strategies against emerging threats.

## 🌟 Features

- **CVE Information Retrieval**: Fetches CVE details from the National Vulnerability Database.
- **EPSS Integration**: Includes Exploit Prediction Scoring System (EPSS) data, offering a probability score for the likelihood of CVE exploitation, aiding in prioritization.
- **Public Exploits Aggregation**: Gathers publicly available exploits, enhancing the understanding of vulnerabilities.
- **CISA KEV**: Shows if the CVE has been listed in the Known Exploited Vulnerabilities (KEV) of CISA.
- **Patching Priority System**: Evaluates and assigns a priority rating for patching based on various factors including public exploits availability.
- **Multi-CVE Support and Export Options**: Supports multiple CVEs in a single run and allows exporting the results to HTML, JSON and CSV formats.
- **Vulnerability Scanner Import**: Import vulnerability scans from popular vulnerability scanners and search directly for known exploits.
- **AI-Powered Risk Assessment**: Leverages OpenAI to provide detailed risk assessments, potential attack scenarios, mitigation recommendations, and executive summaries.
- **User-Friendly Interface**: Easy to use, providing clear and concise information.
- **Comprehensive Security Tool**: Ideal for quick security assessments and staying informed about recent vulnerabilities.

## 💣 Supported Exploit Databases

- **[GitHub](https://poc-in-github.motikan2010.net/)**
- **[ExploitDB](https://www.exploit-db.com/)**
- **[VulnCheck](https://vulncheck.com/)** (requires a **free** VulnCheck API key)
- **[Packet Storm](https://packetstormsecurity.com/)**
- **[Nuclei](https://github.com/projectdiscovery/nuclei-templates)**

## 📁 Supported Vulnerability Scanner Import

- **[Nessus](https://www.tenable.com/products/nessus) (.nessus)**
- **[Nexpose](https://www.rapid7.com/products/nexpose/) (.xml)**
- **[OpenVAS](https://www.openvas.org/) (.xml)**
- **[Docker](https://docs.docker.com/scout/) (.json)**

## 🚀 Usage

### Installation

```shell
$ pip install --user  git+https://github.com/xaitax/SploitScan.git
$ sploitscan

███████╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██████╔╝██║     ██║   ██║██║   ██║   ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║     ███████╗╚██████╔╝██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
v0.9 / Alexander Hagenah / @xaitax / ah@primepage.de

❌ No CVE IDs provided. Please provide CVE IDs or an import file and type.
```

### Regular

```bash
python sploitscan.py CVE-YYYY-NNNNN
```

**Enter one or more CVE IDs to fetch data. Separate multiple CVE IDs with spaces.**

```bash
python sploitscan.py CVE-YYYY-NNNNN CVE-YYYY-NNNNN
```

**Optional: Import functionality. Specify the type: 'nessus', 'nexpose', 'openvas' or 'docker' and import file.**

```bash
python sploitscan.py --import-file path/to/yourfile.nessus --type nessus
```

**Optional: Export the results to a JSON, CSV or HTML file. Specify the format: 'json', 'csv' or 'html'.**

```bash
python sploitscan.py CVE-YYYY-NNNNN -e HTML
```

### Docker

```shell
$ docker build -t sploitscan .
$ docker run --rm sploitscan CVE-2024-1709

With a volume mounted from the current directory

Windows (Powershell)
$ docker run -v ${PWD}:/app --rm sploitscan CVE-2024-1709 -e JSON

Linux
$ docker run -v $(pwd):/app --rm sploitscan CVE-2024-1709 -e JSON
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

### [24. May 2024] - Version 0.9

- **AI-Powered Risk Assessment**: Integrated OpenAI for detailed risk assessments, potential attack scenarios, mitigation recommendations, and executive summaries (needs OpenAI API key).
- **CVE Information Retrieval**: Due to API rate limits and instabilities replaced NIST NVD with [CVE Program](https://github.com/CVEProject/cvelistV5).
- **General Improvements**: Various bug fixes and performance improvements.

### [18. May 2024] - Version 0.8

- **HTML Export Functionality**: Introduced the ability to export vulnerability data to HTML reports.
- **Packet Storm Integration**: Added support for fetching exploit data from Packet Storm.
- **Enhanced Display Functions**: Added CVE_GITHUB_URL as CVE source, and functions to output the most updated CVE source.
- **Code Refactoring**: Refactored code to improve maintainability and readability due to the growing code base.

### [11. May 2024] - Version 0.7

- **Nuclei Template Integration**: Added support for discovery of Nuclei templates, enhancing vulnerability data sources.
- **Enhanced Display Functions**: Refined visual output across all display functions for consistency and readability.
- **General Improvements**: Various bug fixes and performance improvements such as improved error handling.

### [06. May 2024] - Version 0.6.1

- **Import File Capabilities**: Added support for importing vulnerability data directly from Docker Scout scan files.

### [05. May 2024] - Version 0.6

- **Import File Capabilities**: Added support for importing vulnerability data directly from Nessus, Nexpose, and OpenVAS scan files.
- **Expanded Command-Line Options**: Introduced new command-line options to specify the import file and its type.
- **Robust Configuration Management**: Improved error handling for missing or malformed configuration files.
- **General Improvements**: Various bug fixes and performance improvements.

### [02. March 2024] - Version 0.5

- **ExploitDB Integration**: Added support for fetching exploit data from ExploitDB.
- **CVSS Enhancements**: Added support for CVSS 2 and CVSS 3.x
- **Docker support**
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

- [Nilsonfsilva](https://github.com/Nilsonfsilva) for support on Debian packaging.
- [bcoles](https://github.com/bcoles) for bugfixes.
- [Javier Álvarez](https://github.com/jalvarezz13) for bugfixes.
- [Romullo](https://github.com/Romullo) for ideas & suggestions.
- [davidfortytwo](https://github.com/davidfortytwo) for enhancements (Updated CVE retrieval and PacketStorm addition).
- [con-f-use](https://github.com/con-f-use) for support and fixes with setuptools/PyPi.

## 📌 Author

### Alexander Hagenah

- [URL](https://primepage.de)
- [Twitter](https://twitter.com/xaitax)
- [LinkedIn](https://www.linkedin.com/in/alexhagenah)

## 📚 References

- [CVE Program](https://github.com/CVEProject/cvelistV5)
- [FIRST EPSS](https://www.first.org/epss/api)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [nomi-sec PoC-in-GitHub API](https://poc-in-github.motikan2010.net/)
- [VulnCheck](https://vulncheck.com/)
- [ExploitDB](https://www.exploit-db.com/)
- [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei-templates)
- [Packet Storm](https://packetstormsecurity.com/)
- [OpenAI](https://openai.com/)
