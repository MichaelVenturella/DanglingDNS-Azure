# Azure Services Prone to Dangling DNS  

These Azure services are commonly linked to DNS records and can become **dangling** if the associated resource is deleted.  

### 🚨 High-Risk Azure Services:  

| Service                 | Domain Pattern                     |
|-------------------------|-----------------------------------|
| **Azure App Services**  | `*.azurewebsites.net`            |
| **Azure Blob Storage**  | `*.blob.core.windows.net`        |
| **Azure Traffic Manager** | `*.trafficmanager.net`        |
| **Azure CDN**          | `*.azureedge.net`                |
| **Azure Front Door**   | `*.afd.net`                      |

### 🔍 Hunting Tip:  
Regularly check these endpoints when hunting for **dangling DNS** vulnerabilities to prevent subdomain takeovers.  
