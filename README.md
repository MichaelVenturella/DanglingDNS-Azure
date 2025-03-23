# Threat Hunting for Dangling DNS Vulnerabilities in Azure Environments

This repository provides a step-by-step guide and tools to identify and mitigate dangling DNS vulnerabilities in an Azure environment. Dangling DNS occurs when a DNS record (e.g., CNAME) points to a resource that no longer exists, potentially allowing attackers to claim it and perform subdomain takeovers.

## Features
- Enumerate DNS records for an organization’s domain.
- Check if Azure resources tied to those records still exist.
- Identify and mitigate dangling DNS vulnerabilities.

## Prerequisites
- Python 3.8+
- Azure account with permissions to read resource status
- Basic knowledge of DNS and Azure services



## DNS_enum.py Usage
Basic Syntax:
- python dangldns_enum.py <domain> [options]

## Arguments
domain: The target domain to scan (e.g., example.com) [Required].
- -timeout: DNS and HTTP timeout in seconds (default: 5).
- -workers: Maximum number of concurrent workers (default: 10).
- -verbose: Enable debug logging for detailed output.
- -wordlist <file>: Path to a file with subdomain prefixes (e.g., app, mail) to brute-force.
- -subdomains <file>: Path to a file with pre-enumerated subdomains (e.g., app.example.com).
- -skip-enumeration: Skip internal enumeration and use only the provided subdomain list.
- -output <file>: Path to save results in JSON format.


## Workflow Recommendations
For Comprehensive Scans
Enumerate Subdomains: Use a tool like Sublist3r or Amass: 
- sublist3r -d example.com -o subdomains.txt

Run Dangling DNS Enum script:
- python ddangldns_enum.py example.com --subdomains subdomains.txt --skip-enumeration --output results.json
Ensures thorough subdomain discovery followed by targeted CNAME analysis.

## Contributing
- Feel free to submit issues or pull requests to improve the tool. Suggestions for additional enumeration methods or third-party domains are welcome!
