# Security Policy

## Supported Versions

Security fixes are handled for the current release and the `main` branch. Please upgrade to the latest available version before reporting an issue that may already be fixed.

## Reporting a Vulnerability

Please do not open a public GitHub issue for suspected security vulnerabilities.

To report a vulnerability, email the maintainer at [ah@primepage.de](mailto:ah@primepage.de) with:

- a clear description of the vulnerability and impact;
- affected SploitScan version, commit, or installation method;
- steps to reproduce the issue;
- any relevant logs, proof-of-concept details, or suggested fixes.

If GitHub private vulnerability reporting is available for this repository, you may also use the **Security** tab to submit the report privately.

The maintainer will review the report and coordinate disclosure, remediation, and release timing as appropriate.

## Scope

In scope:

- vulnerabilities in SploitScan source code, packaging, release artifacts, and project-maintained configuration examples;
- issues that could expose API keys, local files, or sensitive scan data;
- unsafe handling of vulnerability scanner imports or exported reports.

Out of scope:

- vulnerabilities in third-party services queried by SploitScan;
- public CVE/exploit data returned by external sources;
- findings that require malicious local system access without a SploitScan-specific impact.

## Safe Harbor

Good-faith security research is welcome. Please avoid privacy violations, data destruction, service disruption, and access to data that is not your own while investigating or reporting an issue.
