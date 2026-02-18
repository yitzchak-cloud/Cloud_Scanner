from collections import Counter
from google.cloud import asset_v1

def get_all_project_resources(project_id, region):
    client = asset_v1.AssetServiceClient()
    scope = f"projects/{project_id}"
    
    # שאילתה שמשלבת את האזור הספציפי וגם משאבים גלובליים
    # אנחנו מחפשים: (מיקום המבוקש) או (מיקום גלובלי)
    query = f"location:{region} OR location:global"

    print(f"--- Fetching resources for project: {project_id} (Region: {region} + Global) ---")

    try:
        response = client.search_all_resources(
            scope=scope,
            query=query,
        )

        resource_type_counts = Counter()
        # כאן נשמור גם דוגמה של שמות המשאבים כדי לוודא שמצאנו את ה-VPC
        found_networks = []

        for resource in response:
            resource_type = resource.asset_type.split("/")[-1]
            resource_type_counts[resource_type] += 1
            
            # בדיקה אם זה רשת או סאבנט לצורך הדגמה
            if "Network" in resource_type:
                found_networks.append(resource.display_name)

        if not resource_type_counts:
            print("No resources found.")
            return

        print(f"Found {sum(resource_type_counts.values())} total assets of {len(resource_type_counts)} types.")
        print("--- Resource counts by type ---")
        for resource_type, count in sorted(resource_type_counts.items()):
            print(f"{resource_type}: {count}")

        if found_networks:
            print("\n--- Identified Networks ---")
            for net in set(found_networks): # הסרת כפילויות
                print(f"Found Network: {net}")

    except Exception as e:
        print(f"Query failed: {e}")

MY_PROJECT = "sky-geo-dig-dev-t-cant-1"
MY_REGION = "me-west1"

get_all_project_resources(MY_PROJECT, MY_REGION)