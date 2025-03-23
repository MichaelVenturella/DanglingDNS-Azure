import argparse
import json
import os
from pathlib import Path
from azure.identity import DefaultAzureCredential, AzureCliCredential
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient

def get_azure_subscription_and_group():
    """Automatically retrieve the first available subscription ID and resource group."""
    try:
        # Use Azure CLI credential first (assumes 'az login' has been run)
        credential = AzureCliCredential()
        subscription_client = SubscriptionClient(credential)
        
        # Get the first subscription
        subscriptions = list(subscription_client.subscriptions.list())
        if not subscriptions:
            raise ValueError("No Azure subscriptions found. Please run 'az login' and try again.")
        subscription_id = subscriptions[0].subscription_id
        print(f"Using subscription ID: {subscription_id}")

        # Get resource groups for the subscription
        resource_client = ResourceManagementClient(credential, subscription_id)
        resource_groups = list(resource_client.resource_groups.list())
        if not resource_groups:
            raise ValueError("No resource groups found in the subscription.")
        resource_group = resource_groups[0].name
        print(f"Using resource group: {resource_group}")

        return subscription_id, resource_group
    except Exception as e:
        print(f"Error retrieving Azure subscription or resource group: {e}")
        print("Falling back to environment variables or manual input.")
        return None, None

def check_azure_resource(target, subscription_id, resource_group):
    """Check if an Azure resource exists based on the CNAME target."""
    credential = DefaultAzureCredential()
    
    if "azurewebsites.net" in target:
        web_client = WebSiteManagementClient(credential, subscription_id)
        resource_name = target.split('.')[0]
        try:
            web_client.web_apps.get(resource_group_name=resource_group, name=resource_name)
            return True  # Resource exists
        except Exception:
            return False  # Resource does not exist
    # Add more Azure services here as needed (e.g., Blob Storage)
    return None  # Not an Azure service handled yet

def convert_json_to_txt(json_file, txt_file):
    """Convert dns_enum.py JSON output to the required text format."""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        dns_records = []
        for subdomain, info in data.items():
            if info.get("cname") and info.get("dangling"):
                dns_records.append(f"{subdomain} -> {info['cname']}")
        
        if not dns_records:
            print("No dangling records found in JSON file to convert.")
            return False
        
        with open(txt_file, 'w') as f:
            f.write("\n".join(dns_records))
        print(f"Converted {json_file} to {txt_file} with {len(dns_records)} records.")
        return True
    except Exception as e:
        print(f"Error converting JSON to TXT: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Check Azure resource existence for dangling DNS records.")
    parser.add_argument("--input", help="File with DNS records (txt) or JSON from dns_enum.py")
    parser.add_argument("--output", default="dangling.txt", help="Output file for confirmed dangling records")
    parser.add_argument("--subscription-id", help="Azure subscription ID (optional, auto-detected if not provided)")
    parser.add_argument("--resource-group", help="Azure resource group (optional, auto-detected if not provided)")
    args = parser.parse_args()

    # Determine input type and handle JSON conversion
    input_file = args.input
    temp_txt_file = None
    if input_file and input_file.endswith('.json'):
        temp_txt_file = "temp_dns_records.txt"
        if not convert_json_to_txt(input_file, temp_txt_file):
            print("Failed to convert JSON input. Exiting.")
            return
        input_file = temp_txt_file
    elif not input_file:
        parser.error("--input is required (either a .txt or .json file)")

    # Get subscription ID and resource group
    subscription_id = args.subscription_id
    resource_group = args.resource_group
    if not subscription_id or not resource_group:
        subscription_id, resource_group = get_azure_subscription_and_group()
        if not subscription_id or not resource_group:
            print("Could not auto-detect subscription ID and resource group.")
            print("Please provide them via --subscription-id and --resource-group or set environment variables:")
            print("  export AZURE_SUBSCRIPTION_ID='your-subscription-id'")
            print("  export AZURE_RESOURCE_GROUP='your-resource-group'")
            return

    # Process DNS records
    dangling = []
    try:
        with open(input_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or " -> " not in line:
                    continue
                domain, target = line.split(" -> ")
                exists = check_azure_resource(target, subscription_id, resource_group)
                if exists is False:
                    dangling.append(f"{domain} -> {target}")
                    print(f"Confirmed dangling: {domain} -> {target}")
                elif exists is True:
                    print(f"Active resource: {domain} -> {target}")
                else:
                    print(f"Skipped (not an Azure service handled): {domain} -> {target}")
    except FileNotFoundError:
        print(f"Input file {input_file} not found.")
        return
    except Exception as e:
        print(f"Error processing input file: {e}")
        return

    # Write results
    if dangling:
        with open(args.output, 'w') as f:
            f.write("\n".join(dangling))
        print(f"Confirmed dangling records saved to {args.output} ({len(dangling)} found)")
    else:
        print("No confirmed dangling records found.")

    # Clean up temporary file if created
    if temp_txt_file and Path(temp_txt_file).exists():
        os.remove(temp_txt_file)
        print(f"Cleaned up temporary file: {temp_txt_file}")

if __name__ == "__main__":
    main()
