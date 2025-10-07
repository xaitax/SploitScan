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

## 🌟 Features

- **CVE Information Retrieval**  
  Retrieve detailed information about vulnerabilities.

- **EPSS Integration**  
  Check the likelihood of exploitation with data from the Exploit Prediction Scoring System.

- **Public Exploits Aggregation**  
  Collect publicly available exploit data to help you understand the context of each vulnerability.

- **CISA KEV Integration**  
  Quickly see if a vulnerability is listed in CISA’s Known Exploited Vulnerabilities catalog.

- **AI-Powered Risk Assessment**  
  Get risk assessments using multiple AI providers (OpenAI ChatGPT, Google Gemini, Grok AI, or DeepSeek) that explain potential risks and offer mitigation ideas.

- **HackerOne Reports**  
  Find out if a vulnerability has been involved in HackerOne bug bounty reports, including basic ranking and severity details.

- **Patching Priority System**  
  Receive a simple priority rating for patching based on CVSS, EPSS, and available exploit information.

- **Multi-CVE Support and Export Options**  
  Work with multiple CVEs at once and export the results to HTML, JSON, or CSV formats.

- **Vulnerability Scanner Import**  
  Import scan results from popular vulnerability scanners (Nessus, Nexpose, OpenVAS, Docker) to directly search for known exploits.

- **Granular Method Selection**  
  Choose which specific data retrieval methods to run (such as CISA, EPSS, HackerOne, AI, etc.) so you only get the information you need.

- **Local CVE Database Update & Cloning**  
  Maintain a local copy of the CVE List V5 repository. This lets you update the full CVE data on your machine for offline use and search.

- **Keyword-Based CVE Search Across Sources**  
  Search for CVEs by keywords (for example, “Apple”) across both your local database and remote sources like CISA and Nuclei Templates.

- **Fast Mode for Streamlined Output**  
  Use fast mode to display only the basic CVE information, skipping extra lookups for quicker results.

- **User-Friendly Interface**  
  Enjoy a clear and straightforward interface that presents all the information in an easy-to-read format.


![sploitscan_v0 10 4](https://github.com/user-attachments/assets/4f0ff4fd-9fb4-453f-92a2-f12f41714edd)

## 💣 Supported Exploit Databases

- **[GitHub](https://poc-in-github.motikan2010.net/)**
- **[ExploitDB](https://www.exploit-db.com/)**
- **[VulnCheck](https://vulncheck.com/)** (requires a **free** VulnCheck API key)
- **[Nuclei](https://github.com/projectdiscovery/nuclei-templates)**
- **[Metasploit](https://github.com/rapid7/metasploit-framework)**

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
- **Google Gemini**: Create an account and get an API key at [Google AI Studio](https://aistudio.google.com/app/apikey).
- **xAI Grok**: Create an account and get an API key at [xAI](https://x.ai/api).
- **DeepSeek**: Create an account and get an API key at [DeepSeek](https://platform.deepseek.com/api_keys).

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
    "vulncheck_api_key": "",
    "openai_api_key": "",
    "google_ai_api_key": "",
    "grok_api_key": "",
    "deepseek_api_key": ""
}
```

## 🚀 Usage

```shell
$ python .\sploitscan.py -h

███████╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██████╔╝██║     ██║   ██║██║   ██║   ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║     ███████╗╚██████╔╝██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
v0.14.0 / Alexander Hagenah / @xaitax / ah@primepage.de

usage: sploitscan.py [-h] [-e {json,csv,html}] [-t {nessus,nexpose,openvas,docker}] [--ai {openai,google,grok,deepseek}] [-k KEYWORDS [KEYWORDS ...]] [-local] [-f] [-m METHODS] [-i IMPORT_FILE] [-c CONFIG] [-d] [cve_ids ...]

SploitScan: Retrieve and display vulnerability and exploit data for specified CVE ID(s).

positional arguments:
  cve_ids               Enter one or more CVE IDs (e.g., CVE-YYYY-NNNNN). This is optional if an import file is provided via -i.

options:
  -h, --help            show this help message and exit
  -e {json,csv,html}, --export {json,csv,html}
                        Export the results in the specified format ('json', 'csv', or 'html').
  -t {nessus,nexpose,openvas,docker}, --type {nessus,nexpose,openvas,docker}
                        Specify the type of the import file ('nessus', 'nexpose', 'openvas', or 'docker').
  --ai {openai,google,grok,deepseek}
                        Select the AI provider for risk assessment (e.g., 'openai', 'google', 'grok', or 'deepseek').
  -k KEYWORDS [KEYWORDS ...], --keywords KEYWORDS [KEYWORDS ...]
                        Search for CVEs related to specific keywords (e.g., product name).
  -local, --local-database
                        Download the cvelistV5 repository into the local directory. Use the local database over online research if available.
  -f, --fast-mode       Enable fast mode: only display basic CVE information without fetching additional exploits or data.
  -m METHODS, --methods METHODS
                        Specify which methods to run, separated by commas (e.g., 'cisa,epss,hackerone,ai,prio,references').
  -i IMPORT_FILE, --import-file IMPORT_FILE
                        Path to an import file. When provided, positional CVE IDs can be omitted. The file should be a plain text list with one CVE per line.
  -c CONFIG, --config CONFIG
                        Path to a custom configuration file.
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

### Local CVE Database Update

You can now update (or initially clone) the full CVE List V5 repository locally by using the `--local` option. Note that this repository is several GB in size, so the download may take a while. For example:

```bash
sploitscan -local

███████╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██████╔╝██║     ██║   ██║██║   ██║   ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║     ███████╗╚██████╔╝██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
v0.14.0 / Alexander Hagenah / @xaitax / ah@primepage.de

📥 Cloning CVE List V5 into 'C:\Users\ah/.sploitscan\cvelistV5'.
⚠️ Warning: The repository is several GB in size and the download may take a while.
🔄 Progress: 100.00% - 940.62 MiB | 4.97 MiB/s
✅ CVE List V5 cloned successfully.
```

### Keyword-Based Search Across Sources

Search for CVEs by keywords (e.g., "Apple") across the local database, CISA, and Nuclei Templates.

> [!TIP]
> This can replace more or less replace [searchsploit](https://www.exploit-db.com/searchsploit) as [ExploitDB](https://www.exploit-db.com/) isn't regularly updated anymore. 

```bash
sploitscan -k "Outlook Express"

███████╗██████╗ ██╗      ██████╗ ██╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗██████╔╝██║     ██║   ██║██║   ██║   ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
███████║██║     ███████╗╚██████╔╝██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
v0.14.0 / Alexander Hagenah / @xaitax / ah@primepage.de

┌───[ 🕵️ Searching local database for keywords: outlook express ]
Processing CVE files: 100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 282372/282372 [04:38<00:00, 1013.92it/s]

╔═══════════════════════════════════════════╗
║ Found 48 CVE(s) matching: Outlook Express ║
╚═══════════════════════════════════════════╝

CVE-1999-0967, CVE-1999-1016, CVE-1999-1033, CVE-2000-0036, CVE-2000-0105, CVE-2000-0415, CVE-2000-0524, CVE-2000-0567, CVE-2000-0621, CVE-2000-0653, CVE-2001-0145, CVE-2001-0149, CVE-2001-0945, CVE-2001-0999, CVE-2001-1088, CVE-2001-1325, CVE-2001-1547, CVE-2002-0152, CVE-2002-0285, CVE-2002-0637, CVE-2002-0862, CVE-2002-1121, CVE-2002-1179, CVE-2002-2164, CVE-2002-2202, CVE-2003-0301, CVE-2003-1105, CVE-2003-1378, CVE-2004-0215, CVE-2004-0380, CVE-2004-0526, CVE-2004-2137, CVE-2004-2694, CVE-2005-1213, CVE-2005-2226, CVE-2005-4840, CVE-2006-0014, CVE-2006-2111, CVE-2006-2386, CVE-2006-2766, CVE-2007-2225, CVE-2007-2227, CVE-2007-3897, CVE-2007-4040, CVE-2008-1448, CVE-2008-5424, CVE-2010-0816, CVE-2024-1187

╔═══════════════════════╗
║ CVE ID: CVE-2001-1547 ║
╚═══════════════════════╝

┌───[ 🔍 Vulnerability information ]
|
├ Published:   2005-07-14
├ Base Score:  N/A (N/A)
├ Vector:      N/A
└ Description: Outlook Express 6.0, with "Do not allow attachments to be saved or opened that could potentially be
               a virus" enabled, does not block email attachments from forwarded messages, which
               could allow remote attackers to execute arbitrary code.
[...]
```

### Fast Mode

Enable fast mode to only display basic CVE information (skipping additional lookups).

```bash
sploitscan CVE-2024-1709 --fast-mode
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

Select an AI provider for risk assessment (OpenAI ChatGPT, Google Gemini, Grok AI and DeepSeek).

SploitScan integrates with OpenAI to provide a comprehensive AI-powered risk assessment for each CVE. This feature includes:

- Detailed Risk Assessment: Understand the nature of the vulnerability and its business impact.
- Potential Attack Scenarios: Get descriptions of potential attack scenarios leveraging the vulnerability.
- Mitigation Recommendations: Receive specific, actionable recommendations to mitigate the risk.
- Executive Summary: A concise summary accessible to non-technical stakeholders, highlighting the business impact and urgency.

### Example output

```text

$ sploitscan.py --ai openai CVE-2024-21413

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

- [UjjwalBudha](https://github.com/UjjwalBudha) for ideas & code
- [hexwreaker](https://github.com/hexwreaker) for ideas & code
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

For a detailed list of updates, fixes, and new features, check the [Changelog](CHANGELOG.md).
