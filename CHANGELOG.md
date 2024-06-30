# 📆 Changelog

## [30. June 2024] - Version 0.10.3

- **Main Function Refactoring**: Refactored the main function into smaller, modular functions to improve maintainability and readability.
- **Public Exploit Display Enhancements**: Reworked the public exploit display to include the total number of exploits and better error handling.
- **Improved Error Handling**: Enhanced error handling for API key configurations and data fetching, especially for VulnCheck.

## [30. June 2024] - Version 0.10.2

- **Custom Configuration Path**: Added support for specifying a custom configuration file path using the `--config` or `-c` command-line argument.
- **Platform-Specific Directories**: Added support for platform-specific (*nix, macOS, Windows) configuration directories.
- **Debug Mode**: Improved debug output for configuration file loading.

## [26. June 2024] - Version 0.10

- **HackerOne Integration**: Added support for searching through HackerOne and displays if the CVE was used in any Bug Bounty program including its rank and severity distribution.
- **General Improvements**: Various bug fixes.

## [24. May 2024] - Version 0.9

- **AI-Powered Risk Assessment**: Integrated OpenAI for detailed risk assessments, potential attack scenarios, mitigation recommendations, and executive summaries (needs OpenAI API key).
- **CVE Information Retrieval**: Due to API rate limits and instabilities replaced NIST NVD with [CVE Program](https://github.com/CVEProject/cvelistV5).
- **General Improvements**: Various bug fixes and performance improvements.

### [18. May 2024] - Version 0.8

- **HTML Export Functionality**: Introduced the ability to export vulnerability data to HTML reports.
- **Packet Storm Integration**: Added support for fetching exploit data from Packet Storm.
- **Enhanced Display Functions**: Added CVE_GITHUB_URL as CVE source, and functions to output the most updated CVE source.
- **Code Refactoring**: Refactored code to improve maintainability and readability due to the growing code base.

## [11. May 2024] - Version 0.7

- **Nuclei Template Integration**: Added support for discovery of Nuclei templates, enhancing vulnerability data sources.
- **Enhanced Display Functions**: Refined visual output across all display functions for consistency and readability.
- **General Improvements**: Various bug fixes and performance improvements such as improved error handling.

## [06. May 2024] - Version 0.6.1

- **Import File Capabilities**: Added support for importing vulnerability data directly from Docker Scout scan files.

## [05. May 2024] - Version 0.6

- **Import File Capabilities**: Added support for importing vulnerability data directly from Nessus, Nexpose, and OpenVAS scan files.
- **Expanded Command-Line Options**: Introduced new command-line options to specify the import file and its type.
- **Robust Configuration Management**: Improved error handling for missing or malformed configuration files.
- **General Improvements**: Various bug fixes and performance improvements.

## [02. March 2024] - Version 0.5

- **ExploitDB Integration**: Added support for fetching exploit data from ExploitDB.
- **CVSS Enhancements**: Added support for CVSS 2 and CVSS 3.x
- **Docker support**
- **Code fixes**

## [28. February 2024] - Version 0.4

- **VulnCheck Integration**: Added support for fetching exploit data from VulnCheck, enhancing the exploit information available.
- **API Key Configuration**: Introduced the requirement for a VulnCheck API key, specified in config.json.
- **Requirements satisfied for Debian Integration**

## [17. February 2024] - Version 0.3

- **Additional Information**: Added further information such as references & vector string
- **Removed**: Star count in publicly available exploits

## [15. January 2024] - Version 0.2

- **Multiple CVE Support**: Now capable of handling multiple CVE IDs in a single execution.
- **JSON and CSV Export**: Added functionality to export results to JSON and CSV files.
- **Enhanced CVE Display**: Improved visual differentiation and information layout for each CVE.
- **Patching Priority System**: Introduced a priority rating system for patching, influenced by various factors including the availability of public exploits.

## [13th January 2024] - Version 0.1

- Initial release of SploitScan.