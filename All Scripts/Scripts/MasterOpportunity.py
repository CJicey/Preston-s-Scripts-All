import logging
import requests
import json
import os
import csv
import time
from dotenv import load_dotenv, find_dotenv
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from urllib.parse import quote

load_dotenv(find_dotenv(filename='config.env'))

logging.basicConfig(
    filename='opportunities.log',
    filemode='a',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

###############################################################################
#                                CONFIGURATIONS                               #
###############################################################################

# Year-based prefix for opportunities
current_year_prefix = 'O.25'  

# Where the newly created Opportunities folders will reside in Egnyte.
# This aligns with your scope plan for “Z:\Shared\Opportunities\2025”
CHECK_FOLDER_BASE_PATH = "/Opportunities/2025"
# Location of the template folder if you want to copy subfolders/files in the future.
# Aligns with your scope plan for “Z:\Shared\Team Member Resources\IT\ProjectFolderTemplates\Opportunities”
TEMPLATE_FOLDER_BASE_PATH = "Team Member Resources/IT/ProjectFolderTemplates/Opportunities"

# If you have a CSV-based template guide, you can reference it. Right now, you can leave it blank or remove it.
TEMPLATE_GUIDE = "c:/Scripts/Opportunities/OpportunitiesTemplateGuide.csv"

# Egnyte base, token cache, etc.
EGNYTE_API_BASE = "https://bennettpless.egnyte.com/pubapi/v1"
TOKEN_CACHE_FILE = 'egnyte_token_cache.json'

# Acumatica base, endpoints, etc.
BASE_URL = "https://bennett-pless.acumatica.com"
LOGOFF_ENDPOINT = "/entity/auth/logout"
ACUMATICA_TOKEN_CACHE_FILE = 'acumatica_token_cache.json'

# In-memory dictionary to hold any CSV-based template mappings if needed
template_mapping = {}

###############################################################################
#                           AUTHENTICATION HELPERS                            #
###############################################################################

def load_egnyte_token_from_file():
    """Attempt to load cached Egnyte token from disk."""
    try:
        with open(TOKEN_CACHE_FILE, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_egnyte_token_to_file(token_data):
    """Persist Egnyte token info to disk."""
    with open(TOKEN_CACHE_FILE, 'w') as file:
        json.dump(token_data, file)

def authenticate_egnyte(retry_count=0):
    """Authenticate to Egnyte or use cached token if still valid."""
    current_time = time.time()
    token_data = load_egnyte_token_from_file()

    # Use cached token if it's still valid (assuming a ~1hr token)
    if token_data.get('access_token') and (current_time - token_data.get('timestamp', 0) < 3500):
        print("Using cached Egnyte token...")
        return token_data['access_token']

    if retry_count >= 3:
        print("Maximum Egnyte authentication retries exceeded.")
        return None

    # Gentle wait before re-auth to avoid rate-limiting
    print("Pausing before authenticating to Egnyte to mitigate rate limit risks...")
    time.sleep(5)

    url = "https://bennettpless.egnyte.com/puboauth/token"
    payload = {
        'client_id': os.getenv("EGNYTE_CLIENT_ID"),
        'client_secret': os.getenv("EGNYTE_CLIENT_SECRET"),
        'username': os.getenv("EGNYTE_USERNAME"),
        'password': os.getenv("EGNYTE_PASSWORD"),
        'grant_type': 'password'
    }

    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()
        token_info = response.json()
        new_token_data = {
            'access_token': token_info.get('access_token'),
            'timestamp': current_time
        }
        save_egnyte_token_to_file(new_token_data)
        print("Egnyte token refreshed and cached.")
        return new_token_data['access_token']
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            print(f"Egnyte rate limit exceeded. Retry after {retry_after} seconds.")
            time.sleep(retry_after)
            return authenticate_egnyte(retry_count + 1)
        else:
            print(f"HTTP error occurred during Egnyte authentication: {http_err}")
            print(f"Response was: {response.text}")
    except Exception as err:
        print(f"An error occurred during Egnyte authentication: {err}")

    return None

def authenticate_acumatica():
    """Authenticate to Acumatica using OAuth password flow or return cached token if still valid."""
    # Check for existing, still-valid token
    if os.path.exists(ACUMATICA_TOKEN_CACHE_FILE):
        with open(ACUMATICA_TOKEN_CACHE_FILE, 'r') as file:
            token_data = json.load(file)
            expiration_time = token_data.get('expiration_time')
            if expiration_time and time.time() < expiration_time:
                return token_data['access_token'], token_data['session_id']

    # Otherwise, do a fresh password-based token request.
    base_url = "https://bennett-pless.acumatica.com/identity/connect/token"
    client_id = os.getenv("ACUMATICA_CLIENT_ID")
    client_secret = os.getenv("ACUMATICA_CLIENT_SECRET")
    username = os.getenv("ACUMATICA_USERNAME")
    password = os.getenv("ACUMATICA_PASSWORD")

    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'username': username,
        'password': password,
        'grant_type': 'password',
        'scope': 'api'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.post(base_url, data=payload, headers=headers)
    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data['access_token']
        expires_in = token_data['expires_in']
        session_id = response.cookies.get('ASP.NET_SessionId')

        # Subtract a minute from the expiration to be safe
        expiration_time = time.time() + expires_in - 60

        new_token_data = {
            'access_token': access_token,
            'session_id': session_id,
            'expiration_time': expiration_time
        }
        with open(ACUMATICA_TOKEN_CACHE_FILE, 'w') as file:
            json.dump(new_token_data, file)

        return access_token, session_id
    else:
        raise Exception(f"Failed to authenticate with Acumatica. Status code: {response.status_code}")

def logoff_acumatica(token, session_id):
    """Log off from Acumatica to invalidate the current session and remove local cache file."""
    headers = {
        'Authorization': f'Bearer {token}',
        'Cookie': f'ASP.NET_SessionId={session_id}'
    }
    response = requests.post(f"{BASE_URL}{LOGOFF_ENDPOINT}", headers=headers)
    if response.status_code == 204:
        if os.path.exists(ACUMATICA_TOKEN_CACHE_FILE):
            os.remove(ACUMATICA_TOKEN_CACHE_FILE)
        return True
    else:
        raise Exception(f"Error {response.status_code} logging off: {response.text}")

###############################################################################
#                           OPPORTUNITY DATA HELPERS                          #
###############################################################################

def retrieve_opportunity_data(token, session_id, max_retries=5, delay=10):
    """
    Retrieve Opportunity data from Acumatica. 
    Filter or transform as needed. In your environment, 
    confirm the exact endpoint and fields for Opportunities.
    """
    # Example endpoint: your actual endpoint or version may differ
    api_url = "https://bennett-pless.acumatica.com/entity/BPAcumaticav2/22.200.001/Opportunity"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Cookie": f"ASP.NET_SessionId={session_id}"
    }

    attempts = 0
    while attempts < max_retries:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            raw_response = response.text
            if not raw_response.strip():
                print("No data returned from Opportunities endpoint. Retrying...")
                attempts += 1
                time.sleep(delay)
                continue
            try:
                # If the endpoint returns a list, parse it. If it returns a dictionary,
                # adjust accordingly (some queries use { "value": [ ... ]} in Acumatica).
                opportunities_data = response.json() if raw_response else []
                
                # Some endpoints return {'value': [ ... ]}, others return a direct list
                if isinstance(opportunities_data, dict) and 'value' in opportunities_data:
                    opportunities_data = opportunities_data['value']
                
                # Transform into a list of dict with simpler structure
                processed_opportunities = []
                unique_opportunity_ids = set()
                
                for opp in opportunities_data:
                    # Adjust keys to match the actual fields in your Acumatica instance
                    # Example: 'OpportunityID', 'BusinessAccount', 'Subject', 'Status', etc.
                    opportunity_id = opp.get('OpportunityID', {}).get('value', '')
                    if not opportunity_id or opportunity_id in unique_opportunity_ids:
                        continue
                    unique_opportunity_ids.add(opportunity_id)
                    
                    business_account = opp.get('BusinessAccount', {}).get('value', '')
                    subject = opp.get('Subject', {}).get('value', '')
                    status = opp.get('Status', {}).get('value', '')
                    egnyte_folder = opp.get('EgnyteFolder', {}).get('value', '')
                    
                    processed_opportunities.append({
                        'OpportunityID': opportunity_id,
                        'BusinessAccount': business_account,
                        'Subject': subject,
                        'Status': status,
                        'EgnyteFolder': egnyte_folder
                    })
                
                return processed_opportunities

            except json.JSONDecodeError as e:
                print(f"JSON decoding failed: {e}")
                attempts += 1
                time.sleep(delay)
                continue

        else:
            print(f"Failed to retrieve Opportunity data: {response.status_code}")
            print(f"Response Text: {response.text}")
            attempts += 1
            time.sleep(delay)

    print("Maximum retries exceeded. No data retrieved for Opportunities.")
    return []

def update_opportunity_in_acumatica(opportunity_id, folder_status):
    """
    Update the Opportunity in Acumatica to indicate that 
    the Egnyte folder is created. For example, set EgnyteFolder to 'Created'.
    """
    token, session_id = authenticate_acumatica()
    if not token or not session_id:
        print(f"Failed to authenticate with Acumatica for updating opportunity {opportunity_id}.")
        return

    # We need to find the correct URL for updating a single record.
    # Typically we filter the entity by OpportunityID in the query.
    api_url = (
        f"https://bennett-pless.acumatica.com/entity/"
        f"BPAcumaticav2/22.200.001/Opportunity?$filter=OpportunityID eq '{opportunity_id}'"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Cookie": f"ASP.NET_SessionId={session_id}"
    }

    # We only need to update the EgnyteFolder field, but Acumatica often requires the record 'id'.
    # Step 1: Query for the record's internal 'id'
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        records_data = response.json()
        # if the endpoint returns {'value': [...]}, parse that
        if isinstance(records_data, dict) and 'value' in records_data:
            records_data = records_data['value']
        if not records_data:
            print(f"Opportunity {opportunity_id} not found in Acumatica.")
        else:
            acumatica_internal_id = records_data[0].get("id")
            if not acumatica_internal_id:
                print(f"No Acumatica internal 'id' found for Opportunity {opportunity_id}.")
            else:
                # Step 2: Perform the update (PUT on the same endpoint, but pass the record 'id' and fields)
                update_payload = {
                    "id": acumatica_internal_id,
                    "EgnyteFolder": {"value": "Created"}  # or your desired status
                }
                put_response = requests.put(api_url, headers=headers, json=update_payload)
                if put_response.status_code == 200:
                    print(f"Successfully updated Opportunity {opportunity_id} in Acumatica with Egnyte folder status: 'Created'")
                else:
                    print(f"Failed to update Opportunity {opportunity_id} in Acumatica. Status code: {put_response.status_code}")
                    print(f"Response content: {put_response.content}")
    else:
        print(f"Failed to retrieve Opportunity {opportunity_id} from Acumatica. Status code: {response.status_code}")
        print(f"Response content: {response.content}")

    # Always log off the session
    logoff_acumatica(token, session_id)

###############################################################################
#                          EGNYTE FOLDER OPERATIONS                           #
###############################################################################

def check_folder_exists(egnyte_token, folder_name, opportunity_id):
    """Check if an Egnyte folder already exists. If it does, update Acumatica's EgnyteFolder field."""
    check_url = f"{EGNYTE_API_BASE}/fs/shared/{CHECK_FOLDER_BASE_PATH}/{folder_name}"
    headers = {"Authorization": f"Bearer {egnyte_token}"}

    print(f"Checking if folder exists at: {check_url}")
    response = requests.get(check_url, headers=headers)

    if response.status_code == 200:
        print(f"Folder '{folder_name}' already exists.")
        update_opportunity_in_acumatica(opportunity_id, 'Created')
        return True
    elif response.status_code == 404:
        return False
    else:
        print(f"Failed to check folder existence. Status code: {response.status_code}, response: {response.text}")
        return None

def copy_folder(folder_name, egnyte_token):
    """
    Copy a template folder to the new folder location. If your template is empty or 
    you don’t actually need subfolders, you can skip copying and simply create a new folder.
    """
    # If you prefer just creating an empty folder, you can use the Egnyte CREATE FOLDER API 
    # instead of copying an existing template. 
    # For example:
    #   POST /fs/shared/Opportunities/2025
    # with {"action": "add_folder", "folder_name": new_folder_name}
    # But if you do have a template you want to replicate:
    source_path = f"/Shared/{TEMPLATE_FOLDER_BASE_PATH}"
    destination_path = f"/Shared/{CHECK_FOLDER_BASE_PATH}/{folder_name}"

    print(f"Copying from template: {source_path}")
    print(f"Destination: {destination_path}")

    copy_url = f"{EGNYTE_API_BASE}/fs{source_path}"
    headers = {
        "Authorization": f"Bearer {egnyte_token}",
        "Content-Type": "application/json"
    }
    data = {
        "action": "copy",
        "destination": destination_path,
        "permissions": "keep_original"
    }

    try:
        response = requests.post(copy_url, headers=headers, json=data)
        response.raise_for_status()
        print(f"Folder '{folder_name}' created successfully in Egnyte.")
        return True
    except Exception as e:
        print(f"Failed to copy folder '{folder_name}': {e}")
        return False


###############################################################################
#                           OPPORTUNITY PROCESSING                            #
###############################################################################

def process_opportunity(opportunity, egnyte_token):
    """
    Given a single opportunity record, construct the folder name,
    check if it exists, and if not, create it.
    """
    opp_id = opportunity['OpportunityID']
    business_acct = opportunity['BusinessAccount']
    subj = opportunity['Subject']

    # Construct folder name per your plan:
    # "Opportunity ID – BusinessAccount – Subject"
    folder_name = f"{opp_id} - {business_acct} - {subj}"

    print(f"Processing Opportunity: {opp_id} - {subj}")
    
    exists = check_folder_exists(egnyte_token, folder_name, opp_id)
    if exists is False:
        # If the template folder is currently empty or minimal, you could simply create a new folder
        # using the Egnyte "add_folder" action. Shown here is the "copy_folder" approach for consistency.
        created_ok = copy_folder(folder_name, egnyte_token)
        if created_ok:
            # Update the Opportunity in Acumatica to reflect success
            update_opportunity_in_acumatica(opp_id, 'Created')
        else:
            print(f"Failed to create folder '{folder_name}'.")
    elif exists is True:
        print(f"Folder '{folder_name}' already existed (or was just verified).")
    else:
        print(f"Error checking folder existence for '{folder_name}'. Skipped creation.")


###############################################################################
#                                 MAIN LOGIC                                  #
###############################################################################

def main(egnyte_token):
    """
    A perpetual main loop approach similar to the Proposals script.
    It runs, processes new or open opportunities, sleeps, and repeats.
    """
    while True:
        try:
            print("===== Starting new iteration for Opportunities... =====")
            # 1) Authenticate to Acumatica
            token, session_id = authenticate_acumatica()
            if not token or not session_id:
                print("Failed to authenticate with Acumatica. Will retry in 5 minutes.")
                time.sleep(300)
                continue

            # 2) Retrieve Opportunities
            opportunities = retrieve_opportunity_data(token, session_id)
            print(f"Total opportunities fetched: {len(opportunities)}")

            # 3) Filter for the ones that need Egnyte folder creation
            #    E.g.: Status is "New" or "Open", ID starts with "O.25", and not already "EgnyteFolder = Created"
            #    Adjust the filter logic to match your exact statuses and prefix.
            pending_opps = [
                opp for opp in opportunities
                if opp['OpportunityID'].startswith(current_year_prefix)
                and opp['Status'].lower() in ['new', 'open']
                and opp['EgnyteFolder'].lower() != 'created'
            ]
            print(f"Opportunities requiring folder creation: {len(pending_opps)}")

            time.sleep(5)  # Gentle pause to avoid any rate-limit issues

            # 4) Process each
            for opp in pending_opps:
                try:
                    process_opportunity(opp, egnyte_token)
                except Exception as e:
                    print(f"Error processing Opportunity {opp.get('OpportunityID', 'Unknown')}: {e}")

            # 5) Log off Acumatica and wait
            logoff_acumatica(token, session_id)
            print("Finished processing all pending opportunities in this iteration.")

            # Sleep for 10 minutes (600 seconds) before next cycle
            print("Waiting for 10 minutes before next iteration...")
            time.sleep(600)

        except Exception as main_loop_error:
            print(f"An error occurred in the main opportunities loop: {main_loop_error}")
            print("Waiting for 10 minutes before retrying...")
            time.sleep(600)


if __name__ == "__main__":
    try:
        egnyte_token = authenticate_egnyte()
        if egnyte_token:
            main(egnyte_token)
        else:
            print("Could not obtain Egnyte token. Exiting.")
    except KeyboardInterrupt:
        print("Script execution manually stopped.")