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
```bash
- python dns_enum.py <domain> [options]
```

## Arguments
- -domain: The target domain to scan (e.g., example.com) [Required].
- -timeout: DNS and HTTP timeout in seconds (default: 5).
- -workers: Maximum number of concurrent workers (default: 10).
- -verbose: Enable debug logging for detailed output.
- -wordlist <file>: Path to a file with subdomain prefixes (e.g., app, mail) to brute-force.
- -subdomains <file>: Path to a file with pre-enumerated subdomains (e.g., app.example.com).[This is the recommended option]
- -skip-enumeration: Skip internal enumeration and use only the provided subdomain list.
- -output <file>: Path to save results in JSON format.


## Workflow Recommendations
For Comprehensive Scans
Enumerate Subdomains: Use a tool like Sublist3r or Amass: 
```bash
sublist3r -d example.com -o subdomains.txt
```

Run Dangling DNS Enum script:
```bash
- python dns_enum.py example.com --subdomains subdomains.txt --skip-enumeration --output results.json
```
Ensures thorough subdomain discovery followed by targeted CNAME analysis.

## Contributing
- Feel free to submit issues or pull requests to improve the tool. Suggestions for additional enumeration methods or third-party domains are welcome!


## azure_check.py Usage
## Prerequisites

1. **Install Dependencies**:
   Install the required Python packages using `pip`:

   ```bash
   pip install azure-identity azure-mgmt-web azure-mgmt-resource azure-mgmt-subscription

2. Log in to Azure: Authenticate with Azure using the az login command:
   ```bash
   az login
## Example 1: Using JSON Output from dns_enum.py
1. Run dns_enum.py: Start by running the dns_enum.py script to enumerate DNS records for a domain and output the results to a JSON file:
   ```bash
   python dns_enum.py example.com --output results.json
2. The JSON output will look something like this:
    ```bash
   {
    "app.example.com": {"cname": "myapp.azurewebsites.net", "dangling": true},
    "mail.example.com": {"cname": "mailapp.azurewebsites.net", "dangling": false},
    "staging.example.com": {"cname": "staging.azurewebsites.net", "dangling": true}}
3. Run azure_check.py: Once you have the results.json file, run the azure_check.py script to check which CNAME records are confirmed as dangling:
```bash
 python azure_check.py --input results.json --output confirmed_dangling.txt
```


   
   
