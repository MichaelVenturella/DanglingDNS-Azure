Threat Hunting Methodology for Dangling DNS in Azure
This guide provides a step-by-step process to identify and mitigate dangling DNS vulnerabilities in an Azure environment.

Step 1: Inventory DNS Records
Goal: Collect all DNS records for your organization’s domains.

Manual Method: Export DNS records from your DNS provider (e.g., Route 53, Azure DNS, GoDaddy).
Automated Method: Use dns_enum.py to query CNAME records:

python scripts/dns_enum.py --domain example.com --output dns_records.txt

Output: A list of CNAME records (e.g., sub.example.com -> something.azurewebsites.net).


Step 2: Identify Azure-Linked Records
Goal: Filter records pointing to Azure services.

Review the output from Step 1.
Look for domains like:
*.azurewebsites.net (App Services)
*.blob.core.windows.net (Blob Storage)
*.trafficmanager.net (Traffic Manager)
See azure_services.md for a full list.
Output: A shortlist of Azure-related CNAMEs.
Step 3: Check Azure Resource Existence
Goal: Verify if the Azure resources still exist.

Manual Method: Log into the Azure Portal, search for the resource (e.g., something.azurewebsites.net), and check its status.
Automated Method: Use azure_check.py:

python scripts/azure_check.py --input dns_records.txt --output dangling.txt
Output: A list of CNAMEs pointing to non-existent resources (e.g., deleted App Services).

Step 4: Verify Exploitability
Goal: Confirm if the dangling resource can be claimed.

In your Azure tenant, attempt to create a resource with the same name (e.g., create an App Service named something if something.azurewebsites.net is dangling).
If successful, the CNAME is exploitable.
Caution: Do this in a controlled environment and only with permission.
Step 5: Mitigate Vulnerabilities
Goal: Eliminate the dangling DNS risk.

Option 1: Delete the CNAME record from your DNS provider.
Option 2: Re-provision the Azure resource to reclaim it.
Option 3: Set up Azure monitoring (e.g., Azure Policy) to prevent future dangling records.
Document and report findings to your security team.
Notes
Repeat this process periodically (e.g., monthly) to catch new vulnerabilities.
Ensure you have proper authorization before hunting in a production environment.
