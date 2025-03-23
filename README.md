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
