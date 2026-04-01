# BigQuery Daily Usage Limiter (IAM Deny Policy Enforcer)

An automated, serverless solution for Google Cloud to dynamically block users from executing BigQuery queries once they exceed a daily usage threshold, automatically restoring access at midnight.

## 📖 Background

While Google Cloud provides native custom quotas for BigQuery (e.g., `Query usage per day per user`), there are scenarios where programmatic, custom enforcement is required, including when BigQuery Editions is used but a strict deny rule is still needed. 

Modifying standard IAM **Allow** policies to revoke access is brittle—it destroys state, meaning you don't know who originally had access when it's time to restore it. 

This solution uses **IAM v2 Deny Policies**. Deny policies sit on top of Allow policies and are evaluated first. When a user exceeds their limit, their email is simply appended to a Deny Policy, instantly blocking their query access without touching their underlying group memberships or Allow roles. At midnight, the Deny Policy is wiped clean, and everyone's original access seamlessly resumes.

## 🏗️ Architecture

1. **The Enforcer (Hourly):** A Google Cloud Function triggered by Cloud Scheduler. It queries BigQuery's `INFORMATION_SCHEMA.JOBS` to find users who have exceeded a defined byte threshold *and* had a query finish in the last hour. It then uses the IAM v2 API to append these users to a Project-level Deny Policy.
2. **The Reset (Midnight):** A secondary Cloud Function triggered at 00:01 PT. It simply deletes the Deny Policy entirely, offering a stateless, clean slate for the new day.

## ⚙️ Prerequisites

* **Python:** 3.9+
* **Google Cloud APIs Enabled:**
    * BigQuery API
    * IAM API (`iam.googleapis.com`)
    * Cloud Functions API
    * Cloud Scheduler API
* **Service Account Permissions:** The Service Account running these functions requires:
    * `roles/bigquery.resourceViewer` (To read the Information Schema)
    * `roles/iam.denyAdmin` *(Note: In standard GCP environments, this predefined role is restricted to the Organization level. Ensure your security posture supports this execution).*

## 💻 Codebase

### 1. `requirements.txt`
```text
google-cloud-bigquery==3.11.0
google-cloud-iam==2.12.1
```

### 2. The Enforcer (`main.py`)
Deploy this to run hourly via Cloud Scheduler.

```python
import os
from google.cloud import bigquery
from google.cloud import iam_v2
from google.cloud.iam_v2 import types
from google.api_core.exceptions import NotFound

# --- Configuration ---
PROJECT_ID = os.environ.get("GCP_PROJECT", "your-project-id")
REGION = "region-us" # Update to your region (e.g., 'region-eu' or 'us')
THRESHOLD_BYTES = 2 * (1024 ** 4) # 2 TB in bytes
POLICY_ID = "bq-daily-limit-enforcement"

# IAM v2 Configuration
ATTACHMENT_POINT = f"cloudresourcemanager.googleapis.com%2Fprojects%2F{PROJECT_ID}"
PARENT = f"policies/{ATTACHMENT_POINT}/denypolicies"
POLICY_NAME = f"{PARENT}/{POLICY_ID}"


def get_over_limit_users(bq_client: bigquery.Client) -> list:
    """Queries BigQuery to find users over the daily limit."""
    
    # We check MAX(end_time) to ensure we only process users who had a query 
    # finish in the last hour. This keeps the script stateless and prevents 
    # redundant API calls to update the Deny Policy for already-blocked users.
    query = f"""
        SELECT 
            user_email, 
            SUM(total_bytes_billed) AS total_bytes
        FROM 
            `{PROJECT_ID}.{REGION}.INFORMATION_SCHEMA.JOBS_BY_PROJECT`
        WHERE 
            DATE(creation_time) = CURRENT_DATE()
        GROUP BY 
            user_email
        HAVING 
            total_bytes > {THRESHOLD_BYTES}
            AND MAX(end_time) >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
    """
    
    print(f"Checking BQ for users exceeding {THRESHOLD_BYTES} bytes...")
    try:
        query_job = bq_client.query(query)
        results = query_job.result()
        return [row.user_email for row in results]
    except Exception as e:
        print(f"Error querying BigQuery: {e}")
        return []


def enforce_deny_policy(iam_client: iam_v2.PoliciesClient, over_limit_users: list):
    """Creates or updates the Deny Policy with the over-limit users."""
    
    new_principals = [f"principal://goog/subject/{email}" for email in over_limit_users]
    
    denied_permissions = [
        "[bigquery.googleapis.com/jobs.create](https://bigquery.googleapis.com/jobs.create)",
        "[bigquery.googleapis.com/jobs.createGlobalQuery](https://bigquery.googleapis.com/jobs.createGlobalQuery)"
    ]

    try:
        # 1. Update existing policy
        existing_policy = iam_client.get_policy(request={"name": POLICY_NAME})
        print(f"Found existing Deny Policy: {POLICY_ID}. Updating it...")
        
        current_principals = set()
        if existing_policy.rules:
            current_principals.update(existing_policy.rules[0].deny_rule.denied_principals)
            
        updated_principals = list(current_principals.union(set(new_principals)))
        existing_policy.rules[0].deny_rule.denied_principals = updated_principals
        
        update_request = types.UpdatePolicyRequest(policy=existing_policy)
        operation = iam_client.update_policy(request=update_request)
        operation.result()
        print(f"Successfully updated Deny Policy. Total blocked users: {len(updated_principals)}")

    except NotFound:
        # 2. Create new policy if it doesn't exist
        print(f"Deny Policy {POLICY_ID} not found. Creating a new one...")
        
        deny_rule = types.DenyRule(
            denied_principals=new_principals,
            denied_permissions=denied_permissions
        )

        policy_rule = types.PolicyRule(
            description="Blocks BQ query execution for users over the daily limit.",
            deny_rule=deny_rule
        )

        new_policy = types.Policy(
            name=POLICY_NAME,
            rules=[policy_rule]
        )

        create_request = types.CreatePolicyRequest(
            parent=PARENT,
            policy=new_policy,
            policy_id=POLICY_ID
        )
        
        operation = iam_client.create_policy(request=create_request)
        operation.result()
        print("Successfully created new Deny Policy.")


def enforce_limits(request=None):
    """Entry point for Cloud Function."""
    bq_client = bigquery.Client(project=PROJECT_ID)
    iam_client = iam_v2.PoliciesClient()

    over_limit_users = get_over_limit_users(bq_client)

    if not over_limit_users:
        return ("No new users exceeded the limit in the last hour. No action taken.", 200)

    print(f"Identified {len(over_limit_users)} new users over the limit: {over_limit_users}")

    try:
        enforce_deny_policy(iam_client, over_limit_users)
        return (f"Successfully blocked users: {over_limit_users}", 200)
    except Exception as e:
        print(f"Failed to enforce Deny Policy: {e}")
        return (f"Error: {e}", 500)
```

### 3. The Reset (`reset.py`)
Deploy this as a separate Cloud Function, triggered by Cloud Scheduler daily at `00:01`.

```python
import os
from google.cloud import iam_v2
from google.cloud.iam_v2 import types
from google.api_core.exceptions import NotFound

PROJECT_ID = os.environ.get("GCP_PROJECT", "your-project-id")
POLICY_ID = "bq-daily-limit-enforcement"

ATTACHMENT_POINT = f"cloudresourcemanager.googleapis.com%2Fprojects%2F{PROJECT_ID}"
POLICY_NAME = f"policies/{ATTACHMENT_POINT}/denypolicies/{POLICY_ID}"


def reset_limits(request=None):
    """Entry point for Cloud Function. Deletes the Deny Policy."""
    client = iam_v2.PoliciesClient()

    try:
        print(f"Attempting to delete policy: {POLICY_NAME}")
        delete_request = types.DeletePolicyRequest(name=POLICY_NAME)
        operation = client.delete_policy(request=delete_request)
        operation.result() 
        msg = "Successfully deleted Deny Policy. All BigQuery access restored for the new day!"
        print(msg)
        return (msg, 200)
        
    except NotFound:
        msg = "No Deny Policy found to delete. Everyone already has access."
        print(msg)
        return (msg, 200)
    except Exception as e:
        error_msg = f"Failed to reset Deny Policy: {e}"
        print(error_msg)
        return (error_msg, 500)
```
