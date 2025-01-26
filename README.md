# SploitScan


![SPLOITSCAN-LOGO](https://github.com/xaitax/SploitScan/assets/5014849/05f6641c-2279-456f-9e5a-329926529169)
![Version](https://img.shields.io/github/v/release/xaitax/SploitScan)
![License](https://img.shields.io/github/license/xaitax/SploitScan)


## 📜 Description

SploitScan is a powerful and user-friendly tool designed to streamline the process of identifying exploits for known vulnerabilities and their respective exploitation probability. Empowering cybersecurity professionals with the capability to swiftly identify and apply known and test exploits. It's particularly valuable for professionals seeking to enhance their security measures or develop robust detection strategies against emerging threats.

## 📖 Table of contents

- 📜 [Description](#-description)
- 🌟 [Features](#-features)
- 💣 [Supported Exploit Databases](#-supported-exploit-databases)
- 📁 [Supported Vulnerability Scanner Import](#-supported-vulnerability-scanner-import)
- ⚙️ [Installation](#️-installation)
- 🚀 [Usage](#-usage)
- 🤖 [AI-Powered Risk Assessment](#-ai-powered-risk-assessment)
- 🛡️ [Patching Priority System](#️-patching-priority-system)
- 🫱🏼‍🫲🏽 [Contributing](#-contributing)
- 📌 [Author](#-author)
- 📆 [Changelog](#-changelog)
- 📚 [References](#-references)

## 🌟 Features

- **CVE Information Retrieval**: Fetches CVE details from the National Vulnerability Database.
- **EPSS Integration**: Includes Exploit Prediction Scoring System (EPSS) data, offering a probability score for the likelihood of CVE exploitation, aiding in prioritization.
- **Public Exploits Aggregation**: Gathers publicly available exploits, enhancing the understanding of vulnerabilities.
- **CISA KEV**: Shows if the CVE has been listed in the Known Exploited Vulnerabilities (KEV) of CISA.
- **AI-Powered Risk Assessment**: Leverages OpenAI to provide detailed risk assessments, potential attack scenarios, mitigation recommendations, and executive summaries.
- **HackerOne Reports**: Shows if the CVE was used within HackerOne Bug Bounty programs including their total rank overall and severity distribution.
- **Patching Priority System**: Evaluates and assigns a priority rating for patching based on various factors including public exploits availability.
- **Multi-CVE Support and Export Options**: Supports multiple CVEs in a single run and allows exporting the results to HTML, JSON and CSV formats.
- **Vulnerability Scanner Import**: Import vulnerability scans from popular vulnerability scanners and search directly for known exploits.
- **Granular Method Selection**: Only specific methods (e.g., `cisa`, `epss`, `hackerone`, `ai`, etc.), giving you control over what data you want to retrieve.
- **User-Friendly Interface**: Easy to use, providing clear and concise information.
- **Comprehensive Security Tool**: Ideal for quick security assessments and staying informed about recent vulnerabilities.

![sploitscan_v0 10 4](https://github.com/user-attachments/assets/4f0ff4fd-9fb4-453f-92a2-f12f41714edd)

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

## ⚙️ Installation

### GitHub

```shell
git clone https://github.com/xaitax/SploitScan.git
cd sploitscan
pip install -r requirements.txt
```

### pip

```shell
pip install --user sploitscan
```

### Kali/Ubuntu/Debian (might not the latest version)

```shell
apt install sploitscan
```

### Obtaining API Keys

- **VulnCheck**: Sign up for a free account at [VulnCheck](https://vulncheck.com/) to get your API key.
- **OpenAI**: Create an account and get an API key at [OpenAI](https://platform.openai.com/signup/).

### Configuration File

SploitScan searches for a `config.json` in multiple locations by default. It will load the first valid file it finds, in this order:

1. **Custom path passed via `--config` or `-c`**  
2. **Environment variable**: `SPLOITSCAN_CONFIG_PATH`  
3. **Local and standard config-file locations**:  
   - Current working directory  
   - `~/.sploitscan/config.json`  
   - `~/.config/sploitscan/config.json`  
   - `~/Library/Application Support/sploitscan/config.json` (macOS)  
   - `%APPDATA%/sploitscan/config.json` (Windows)  
   - `/etc/sploitscan/config.json`

> **Note**: Only one file is loaded — the first one found in the above sequence. You can place your `config.json` in any of these paths.

A typical `config.json` might look like this:

```json
{
  "vulncheck_api_key": "your_vulncheck_api_key",
  "openai_api_key": "your_openai_api_key"
}
```

## 🚀 Usage

```shell
$ sploitscan.py -h

███████╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██████╔╝██║     ██║   ██║██║   ██║   ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║     ███████╗╚██████╔╝██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
v0.12.0 / Alexander Hagenah / @xaitax / ah@primepage.de

usage: sploitscan.py [-h] [-e {json,JSON,csv,CSV,html,HTML}] [-t {nessus,nexpose,openvas,docker}] [-m METHODS] [-i IMPORT_FILE] [-c CONFIG] [-d] [cve_ids ...]

SploitScan: Retrieve and display vulnerability data as well as public exploits for given CVE ID(s).

positional arguments:
  cve_ids               Enter one or more CVE IDs to fetch data. Separate multiple CVE IDs with spaces. Format for each ID: CVE-YYYY-NNNNN. This argument is optional if an import file is provided
                        using the -i option.

options:
  -h, --help            show this help message and exit
  -e {json,JSON,csv,CSV,html,HTML}, --export {json,JSON,csv,CSV,html,HTML}
                        Optional: Export the results to a JSON, CSV, or HTML file. Specify the format: 'json', 'csv', or 'html'.
  -t {nessus,nexpose,openvas,docker}, --type {nessus,nexpose,openvas,docker}
                        Specify the type of the import file: 'nessus', 'nexpose', 'openvas' or 'docker'.
  -m METHODS, --methods METHODS
                        Specify which methods to run, separated by commas. Options: 'cisa', 'epss', 'hackerone', 'ai', 'prio', 'references', etc.
  -i IMPORT_FILE, --import-file IMPORT_FILE
                        Path to an import file. If used, CVE IDs can be omitted from the command line arguments. Expected file type is a plain text file with one CVE per line. Vulnerability scanner
                        files can be imported also with the --type argument to specify the correct type
  -c CONFIG, --config CONFIG
                        Path to a custom config file.
  -d, --debug           Enable debug output.
```

### Single CVE Query

```bash
sploitscan CVE-2024-1709
```

### Multiple CVE Query

```bash
sploitscan CVE-2024-1709 CVE-2024-21413
```

### Import from Vulnerability Scanner

Specify the type: 'nessus', 'nexpose', 'openvas', or 'docker' and provide the file path.

```bash
sploitscan --import-file path/to/yourfile.nessus --type nessus
```

### Select Specific Methods

To run only specific data retrieval methods (e.g., CISA, EPSS, AI risk assessment), use the `-m` argument:

```bash
sploitscan CVE-2024-1709 -m cisa,epss
```

### Export Results

Specify the export format: 'json', 'csv', or 'html'.

```bash
sploitscan CVE-2024-1709 -e html
```

### Docker

Ensure you have Docker installed. For installation instructions, see [Docker's official installation guide](https://docs.docker.com/get-docker/).

To build and run SploitScan in Docker:

```shell
docker build -t sploitscan .
docker run --rm sploitscan CVE-2024-1709
```

With a volume mounted from the current directory

#### Windows (Powershell)

```shell
docker run -v ${PWD}:/app --rm sploitscan CVE-2024-1709 -e JSON
```

#### Linux

```shell
docker run -v $(pwd):/app --rm sploitscan CVE-2024-1709 -e JSON
```

## 🤖 AI-Powered Risk Assessment

SploitScan integrates with OpenAI to provide a comprehensive AI-powered risk assessment for each CVE. This feature includes:

- Detailed Risk Assessment: Understand the nature of the vulnerability and its business impact.
- Potential Attack Scenarios: Get descriptions of potential attack scenarios leveraging the vulnerability.
- Mitigation Recommendations: Receive specific, actionable recommendations to mitigate the risk.
- Executive Summary: A concise summary accessible to non-technical stakeholders, highlighting the business impact and urgency.

### Example output

```text

$ sploitscan.py CVE-2024-21413

[...]

┌───[ 🤖 AI-Powered Risk Assessment ]
|
| 1. Risk Assessment
| -------------------
| The vulnerability identified by CVE-2024-21413 is a critical remote code execution flaw in
| Microsoft Outlook with a CVSS score of 9.8. The impact on business operations can be severe due to
| its high potential to be exploited over a network without any user interactions or elevated
| privileges. This unvalidated input vulnerability (CWE-20) could allow an attacker to execute
| arbitrary code on the target system, thereby compromising the confidentiality, integrity, and
| availability of critical business data and systems. Given its critical rating and the existence of
| multiple exploits on public repositories like GitHub, the likelihood of exploitation is very high.
| This necessitates immediate attention from the security teams to mitigate the risks associated.
|
| 2. Potential Attack Scenarios
| ------------------------------
| An attacker could exploit this vulnerability by sending a specially crafted email to a victim
| using Microsoft Outlook. Once the email is opened or previewed, the malicious payload would
| execute, allowing the attacker to gain control over the victim's system. The process involves: 1.
| Crafting a malicious email leveraging the specific flaw in email handling within Microsoft
| Outlook. 2. Sending the email to the intended victim. 3. Upon opening or previewing the email, the
| victim’s system executes the malicious code. The potential outcomes of this attack include theft
| of sensitive information, installation of malware or ransomware, and compromising other systems
| within the same network due to lateral movement capabilities.
|
| 3. Mitigation Recommendations
| ------------------------------
| Immediate mitigation recommendation includes: 1. Applying the latest security patches provided by
| Microsoft. Reference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413 2.
| Implementing network-level protections such as email filtering and network segmentation to limit
| the spread of potential infections. 3. Conducting regular security awareness training for users to
| recognize phishing and malicious emails. 4. Monitoring network and system activity for signs of
| suspicious behavior and unauthorized execution. 5. Regularly backing up critical data and ensuring
| the integrity of backups.
|
| 4. Executive Summary
| ---------------------
| CVE-2024-21413, a critical remote code execution vulnerability in Microsoft Outlook, poses a
| significant risk to businesses due to its potential to be exploited without user interaction.
| Multiple exploit proofs are publicly available, increasing the likelihood of attacks.
| Organizations must act swiftly by applying the necessary patches from Microsoft, enhancing their
| email security protocols, and educating their staff to identify potential phishing attempts.
| Mitigating this vulnerability is essential to protect sensitive information, maintain business
| integrity, and ensure system availability, thus preventing potential financial and reputational
| damage. Immediate action is crucial to safeguard the organization against this severe threat.
|
└────────────────────────────────────────
```

## 🛡️ Patching Priority System

The Patching Prioritization System in SploitScan provides a strategic approach to prioritizing security patches based on the severity and exploitability of vulnerabilities. It's influenced by the model from [CVE Prioritizer](https://github.com/TURROKS/CVE_Prioritizer), with enhancements for handling publicly available exploits. Here's how it works:

- A+ Priority: Assigned to CVEs listed in CISA's KEV or those with publicly available exploits. This reflects the highest risk and urgency for patching.
- A to D Priority: Based on a combination of CVSS scores and EPSS probability percentages. The decision matrix is as follows:
  - A: CVSS score >= 6.0 and EPSS score >= 0.2. High severity with a significant probability of exploitation.
  - B: CVSS score >= 6.0 but EPSS score < 0.2. High severity but lower probability of exploitation.
  - C: CVSS score < 6.0 and EPSS score >= 0.2. Lower severity but higher probability of exploitation.
  - D: CVSS score < 6.0 and EPSS score < 0.2. Lower severity and lower probability of exploitation.

This system assists users in making informed decisions on which vulnerabilities to patch first, considering both their potential impact and the likelihood of exploitation. Thresholds can be changed to your business needs.

## 🫱🏼‍🫲🏽 Contributing

Contributions are welcome! Whether it's fixing bugs, adding new features, or improving the documentation, feel free to fork the repository and submit a pull request. You can also report issues or suggest enhancements through the GitHub issue tracker.

Special thanks to:

- [Nilsonfsilva](https://github.com/Nilsonfsilva) for support on Debian packaging.
- [bcoles](https://github.com/bcoles) for bugfixes.
- [Javier Álvarez](https://github.com/jalvarezz13) for bugfixes.
- [Romullo](https://github.com/Romullo) for ideas & suggestions.
- [davidfortytwo](https://github.com/davidfortytwo) for enhancements (Updated CVE retrieval and PacketStorm addition).
- [con-f-use](https://github.com/con-f-use) for support and fixes with setuptools/PyPi.
- [Martijn Russchen](https://github.com/martijnrusschen) for his feedback and idea on HackerOne GraphQL.

## 📌 Author

### Alexander Hagenah

- [URL](https://primepage.de)
- [Twitter](https://twitter.com/xaitax)
- [LinkedIn](https://www.linkedin.com/in/alexhagenah)

## 📆 Changelog

- For a detailed list of updates, fixes, and new features, check the [Changelog](CHANGELOG.md).

## 📚 References

- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CVE Program](https://github.com/CVEProject/cvelistV5)
- [ExploitDB](https://www.exploit-db.com/)
- [FIRST EPSS](https://www.first.org/epss/api)
- [HackerOne](https://hackerone.com/)
- [nomi-sec PoC-in-GitHub API](https://poc-in-github.motikan2010.net/)
- [OpenAI](https://openai.com/)
- [Packet Storm](https://packetstormsecurity.com/)
- [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei-templates)
- [VulnCheck](https://vulncheck.com/)

