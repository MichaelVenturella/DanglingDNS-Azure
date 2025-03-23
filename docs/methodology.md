# Threat Hunting Methodology for Dangling DNS in Azure  

This guide provides a step-by-step process to identify and mitigate **dangling DNS** vulnerabilities in an Azure environment.  

---  

## Step 1: Inventory DNS Records  

### 🎯 Goal:  
Collect all DNS records for your organization’s domains.  

### Methods:  

#### 🔹 Manual Method  
- Export DNS records from your DNS provider, such as:  
  - **AWS Route 53**  
  - **Azure DNS**  
  - **GoDaddy**  

#### 🔹 Automated Method  
- Use the following script to query CNAME records:  

  ```bash
  python scripts/dns_enum.py --domain example.com --output dns_records.txt



## Step 2: Identify Azure-Linked Records  

### Goal:  
Filter records pointing to Azure services.  

### Steps:  
1. Review the output from **Step 1**.  
2. Look for domains matching Azure services, such as:  
   - `*.azurewebsites.net` (App Services)  
   - `*.blob.core.windows.net` (Blob Storage)  
   - `*.trafficmanager.net` (Traffic Manager)  
3. Refer to **[azure_services.md](azure_services.md)** for a full list.  

### Output:  
A shortlist of Azure-related CNAMEs.  

---  

## Step 3: Check Azure Resource Existence  

### Goal:  
Verify if the Azure resources still exist.  

### Methods:  

#### 🔹 Manual Method  
- Log into the **Azure Portal**.  
- Search for the resource (e.g., `something.azurewebsites.net`).  
- Check its status.  

#### 🔹 Automated Method  
- Run the following script:  

  ```bash
  python scripts/azure_check.py --input dns_records.txt --output dangling.txt


## Step 4: Verify Exploitability  

### Goal:  
Confirm if the dangling resource can be claimed.  

### Steps:  
1. In your Azure tenant, attempt to create a resource with the same name.  
   - Example: Try creating an **App Service** with the name `something` if `something.azurewebsites.net` is dangling.  
2. If successful, the CNAME is exploitable.  

⚠ **Caution:** Perform this in a controlled environment and only with proper authorization.  

---  

## Step 5: Mitigate Vulnerabilities  

### Goal:  
Eliminate the dangling DNS risk.  

### Mitigation Options:  
- **Option 1:** Delete the CNAME record from your DNS provider.  
- **Option 2:** Re-provision the Azure resource to reclaim it.  
- **Option 3:** Implement Azure monitoring (e.g., Azure Policy) to prevent future dangling records.  

📌 **Action Item:** Document and report findings to your security team.  

---  

## Notes  
✅ Repeat this process periodically (e.g., monthly) to catch new vulnerabilities.  
🔒 Ensure you have proper authorization before performing this in a production environment.  

