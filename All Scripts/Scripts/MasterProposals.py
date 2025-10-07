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

# Load environment variables from a local config file in the working directory (or nearest match)
# This is where ACUMATICA_* and EGNYTE_* credentials are expected to be defined
load_dotenv(find_dotenv(filename='config.env'))

# Configure file-based logging for traceability and auditing of each run
logging.basicConfig(filename='proposals.log',
                    filemode='a',
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)

# Proposal number prefix filter (year-coupled). Example: "P.25"
current_year_prefix = 'P.25'

# Egnyte destination base path for proposal folders (under /Shared)
CHECK_FOLDER_BASE_PATH = "/Bennett & Pless Leicht/Proposals/2025"

# Egnyte template location (under /Shared), used when copying the proposal folder skeleton
TEMPLATE_FOLDER_BASE_PATH = "Team Member Resources/IT/ProjectFolderTemplates"

# CSV file mapping conditions to template names (future extensibility for different templates)
TEMPLATE_GUIDE = "c:/Scripts/BPL Proposals/BPLProposalTemplateGuide.csv"

# Egnyte REST API base
EGNYTE_API_BASE = "https://bennettpless.egnyte.com/pubapi/v1"

# Local JSON file to cache Egnyte access tokens with timestamps (reduce auth calls)
TOKEN_CACHE_FILE = 'egnyte_token_cache.json'

# Acumatica base & logoff endpoint
BASE_URL = "https://bennett-pless.acumatica.com"
LOGOFF_ENDPOINT = "/entity/auth/logout"

# Local JSON file to cache Acumatica token + session ID + expiration
ACUMATICA_TOKEN_CACHE_FILE = 'acumatica_token_cache.json'

# In-memory token holder (not strictly needed since file cache is used)
EGNYTE_TOKEN_CACHE = {
    'access_token': None,
    'timestamp': None
}

def load_template_mapping(template_guide_path='c:/Scripts/BPL Proposals/BPLProposalTemplateGuide.csv'):
    # Load a mapping of ConditionSet -> TemplateName from a CSV.
    # This supports selecting different Egnyte templates per proposal attributes.
    global template_mapping
    template_mapping = {}
    try:
        with open(template_guide_path, mode='r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                #print(f"CSV Row: {row}")
                condition_set = row['ConditionSet'].strip()
                template_name = row['TemplateName'].strip()
                #print(f"Loading mapping for proposals: {condition_set} -> {template_name}")
                template_mapping[condition_set] = template_name
    except FileNotFoundError:
        print(f"Template guide file not found: {template_guide_path}")
    except Exception as e:
        print(f"Error loading template mapping from {template_guide_path}: {e}")

# Pre-load template mapping at import time so first iteration has it available
load_template_mapping('c:/Scripts/BPL Proposals/BPLProposalTemplateGuide.csv')

def authenticate_acumatica():
    # Return a valid (access_token, session_id), using a local cache if still fresh
    if os.path.exists(ACUMATICA_TOKEN_CACHE_FILE):
        with open(ACUMATICA_TOKEN_CACHE_FILE, 'r') as file:
            token_data = json.load(file)
            expiration_time = token_data.get('expiration_time')
            if expiration_time and time.time() < expiration_time:
                return token_data['access_token'], token_data['session_id']

    # Acquire a fresh token via password grant against Acumatica Identity
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
        # ASP.NET_SessionId cookie is required by entity endpoints
        session_id = response.cookies.get('ASP.NET_SessionId')

        # Cache with a 60s buffer to avoid edge-of-expiry requests
        expiration_time = time.time() + expires_in - 60

        token_data = {
            'access_token': access_token,
            'session_id': session_id,
            'expiration_time': expiration_time
        }
        with open(ACUMATICA_TOKEN_CACHE_FILE, 'w') as file:
            json.dump(token_data, file)

        return access_token, session_id
    else:
        # Bubble up details for troubleshooting (bad credentials, disabled user, etc.)
        raise Exception(f"Failed to authenticate with Acumatica. Status code: {response.status_code}")

def logoff_acumatica(token, session_id):
    # Politely end the Acumatica session and remove the local token cache if successful
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
        # If logoff fails, surface the error; caller handles loop continuation
        raise Exception(f"Error {response.status_code} logging off: {response.text}")

def load_egnyte_token_from_file():
    # Read Egnyte token cache (access_token + timestamp) if present
    try:
        with open(TOKEN_CACHE_FILE, 'r') as file:
            token_data = json.load(file)
            return token_data
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_egnyte_token_to_file(token_data):
    # Persist Egnyte token data to disk between iterations and restarts
    with open(TOKEN_CACHE_FILE, 'w') as file:
        json.dump(token_data, file)

def authenticate_egnyte(retry_count=0):
    # Return a valid Egnyte access token, reusing cached token if still fresh (~<3500s old)
    current_time = time.time()
    token_data = load_egnyte_token_from_file()

    if token_data.get('access_token') and (current_time - token_data.get('timestamp', 0) < 3500):
        print("Using cached token...")
        return token_data['access_token']

    # Basic retry guard to avoid infinite retries upon persistent failures/rate limits
    if retry_count >= 3:
        print("Maximum authentication retries exceeded.")
        return None

    # Small delay helps avoid immediate rate limits when in tight loops
    print("Pausing before authenticating to mitigate rate limit risks...")
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
        token_data = {
            'access_token': token_info.get('access_token'),
            'timestamp': current_time
        }
        save_egnyte_token_to_file(token_data)
        print("Token refreshed and cached.")
        return token_data['access_token']
    except requests.exceptions.HTTPError as http_err:
        # If rate limited, honor Retry-After then recursively retry (bounded by retry_count)
        if response.status_code == 429:
            retry_after = int(response.headers.get("Retry-After", 60))
            print(f"Rate limit exceeded. Retry after {retry_after} seconds.")
            time.sleep(retry_after)
            return authenticate_egnyte(retry_count + 1)
        else:
            print(f"HTTP error occurred: {http_err}")
            print(f"Response was: {response.text}")
    except Exception as err:
        print(f"An error occurred: {err}")

    return None

def check_folder_exists(egnyte_token, folder_name, proposal_nbr):
    # Check Egnyte for the presence of the destination folder; if present, update Acumatica to "Created"
    check_url = f"{EGNYTE_API_BASE}/fs/shared/{CHECK_FOLDER_BASE_PATH}/{folder_name}"

    headers = {
        "Authorization": f"Bearer {egnyte_token}"
    }

    response = requests.get(check_url, headers=headers)
    print(f"Checking if folder exists: {check_url}")
    if response.status_code == 200:
        # Folder exists -> mark the proposal in Acumatica as having its Egnyte folder created
        update_proposal_in_acumatica(proposal_nbr, folder_name)
        return True
    elif response.status_code == 404:
        # Folder not found
        return False
    else:
        # Any other status indicates auth/path issues; return None to signal "unknown"
        print(f"Failed to check folder: {response.status_code}")
        print(f"Response Text: {response.text}")
        return None
    
def copy_folder(folder_name, egnyte_token):
    # Copy the standard "BPL Proposal" template to the project-specific destination path
    source_path = f"/Shared/{TEMPLATE_FOLDER_BASE_PATH}/BPL Proposal"
    destination_path = f"/Shared/{CHECK_FOLDER_BASE_PATH}/{folder_name}"
    
    print(f"Copying folder to: {destination_path}")

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
        print(f"Folder '{folder_name}' created successfully.")
        return True
    except Exception as e:
        print(f"Failed to create folder '{folder_name}': {e}")
        return False

def rename_folder(egnyte_token, old_path, new_folder_name):
    # Rename/move an Egnyte folder by posting an action=move to the old path with a new destination
    url = f"https://bennettpless.egnyte.com/pubapi/v1/fs/{old_path}"
    
    headers = {
        "Authorization": f"Bearer {egnyte_token}",
        "Content-Type": "application/json"
    }
    data = {
        "action": "move",
        "destination": f"{new_folder_name}"
    }
    
    response = requests.post(url, headers=headers, json=data)
    
    if response.status_code in [200, 201]:
        print(f"Folder renamed successfully to {new_folder_name}")
        return True
    else:
        print(f"Failed to rename folder. Status Code: {response.status_code}, Response: {response.text}")
        return False

def set_permissions():
    # Placeholder for future permission-setting on newly created Egnyte folders
    pass

def load_template_mapping(template_guide_path='c:/Scripts/BPL Proposals/BPLProposalTemplateGuide.csv'):
    # Duplicated definition (kept as-is): loads CSV mapping and prints rows for debugging
    global template_mapping
    template_mapping = {}
    try:
        with open(template_guide_path, mode='r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                print(f"CSV Row: {row}")
                condition_set = row['ConditionSet'].strip()
                template_name = row['TemplateName'].strip()
                print(f"Loading mapping for proposals: {condition_set} -> {template_name}")
                template_mapping[condition_set] = template_name
    except FileNotFoundError:
        print(f"Template guide file not found: {template_guide_path}")
    except Exception as e:
        print(f"Error loading template mapping from {template_guide_path}: {e}")


def determine_template_path(proposal_attributes):
    # Rudimentary template selection: currently always picks 'BPL Proposal' unless you extend mappings
    global template_mapping
    if not template_mapping:
        load_template_mapping()

    selected_template = template_mapping.get('ConditionSet1', 'BPL Proposal')

    print(f"Proposal '{proposal_attributes['ProposalNbr']}', Attributes: {proposal_attributes}, Template Selected: '{selected_template}'")

    return selected_template

def retrieve_proposal_data(token, session_id, max_retries=5, delay=10):
    # Pull all proposals for Branch == 'BPL' from Acumatica; return a deduped, normalized list of dicts
    api_url = "https://bennett-pless.acumatica.com/entity/BPAcumaticav2/22.200.001/Proposals?$filter=Branch eq 'BPL'"
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
            #print(f"Raw Response: {raw_response}")
            try:
                proposals_data = response.json() if raw_response else []
                #print(f"Proposals Data: {proposals_data}")
                
                formatted_proposals = []
                unique_proposal_numbers = set()
                for proposal in proposals_data:
                    proposal_number = proposal.get('ProposalNbr', {}).get('value', '')
                    if proposal_number not in unique_proposal_numbers:
                        unique_proposal_numbers.add(proposal_number)
                        formatted_proposals.append({
                            'ProposalNbr': proposal_number,
                            'Status': proposal.get('Status', {}).get('value', ''),
                            'Amount': proposal.get('Amount', {}).get('value', 0),
                            'CompanyName': proposal.get('CompanyName', {}).get('value', ''),
                            'ProjectID': proposal.get('ProjectID', {}).get('value', ''),
                            'BusinessAccount': proposal.get('BusinessAccount', {}).get('value', ''),
                            'Date': proposal.get('Date', {}).get('value', ''),
                            'Department': proposal.get('Department', {}).get('value', ''),
                            'ProjectDescription': proposal.get('ProjectDescription', {}).get('value', ''),
                            'Branch': proposal.get('Branch', {}).get('value', ''),
                            'EgnyteFolder': proposal.get('EgnyteFolder', {}).get('value', '')
                        })
                
                return formatted_proposals
            except json.JSONDecodeError as e:
                # Retry on transient JSON parse/network issues
                print(f"JSON decoding failed: {e}")
                attempts += 1
                time.sleep(delay)
                continue
        else:
            # Non-200: log & retry after delay
            print(f"Failed to retrieve proposal data: {response.status_code}")
            print(f"Response Text: {response.text}")
            attempts += 1
            time.sleep(delay)
            continue
    
    print("Maximum retries exceeded. No data retrieved.")
    logoff_acumatica(token, session_id)
    return []

def update_proposal_in_acumatica(proposal_nbr, folder_name):
    # Sets EgnyteFolder="Created" on the target proposal, using a GET to fetch id and a PUT to update
    token, session_id = authenticate_acumatica()
    if not token or not session_id:
        print(f"Failed to authenticate with Acumatica for updating proposal {proposal_nbr}.")
        return

    api_url = f"https://bennett-pless.acumatica.com/entity/BPAcumaticav2/22.200.001/Proposals?$filter=ProposalNbr eq '{proposal_nbr}'&$select=EgnyteFolder"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Cookie": f"ASP.NET_SessionId={session_id}"
    }

    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        proposal_data = response.json()
        if proposal_data:
            proposal_id = proposal_data[0]["id"]
            data = {
                "id": proposal_id,
                "EgnyteFolder": {"value": "Created"}
            }
            response = requests.put(api_url, headers=headers, json=data)
            if response.status_code == 200:
                print(f"Successfully updated proposal {proposal_nbr} in Acumatica with Egnyte folder status: 'Created'")
            else:
                print(f"Failed to update proposal {proposal_nbr} in Acumatica. Status code: {response.status_code}")
                print(f"Response content: {response.content}")
                print(f"Request data: {data}")
        else:
            print(f"Proposal {proposal_nbr} not found in Acumatica.")
    else:
        print(f"Failed to retrieve proposal {proposal_nbr} from Acumatica. Status code: {response.status_code}")
        print(f"Response content: {response.content}")

    logoff_acumatica(token, session_id)

def process_proposal(proposal, egnyte_token):
    # Process a single proposal: build folder name, check/create folder, update Acumatica when created
    print(f"Processing proposal: {proposal['ProposalNbr']} - {proposal['CompanyName']}")

    folder_name = f"{proposal['ProposalNbr']} - {proposal['BusinessAccount']} - {proposal['ProjectDescription']}"

    proposal_attributes = {
        'folder_name': folder_name,
        'ProjectID': proposal['ProjectID'],
        'Department': proposal['Department'],
        'Status': proposal['Status'],
        'Amount': proposal['Amount'],
        'BusinessAccount': proposal['BusinessAccount'],
        'Date': proposal['Date'],
        'Branch': proposal['Branch'],
        'EgnyteFolder': proposal['EgnyteFolder']
    }

    print(f"During Main.py Process_Proposal, The Status for Proposal '{proposal['ProposalNbr']}': {proposal['Status']}")

    if not check_folder_exists(egnyte_token, folder_name, proposal['ProposalNbr']):
        print(f"Debug: Proposal Attributes: {proposal_attributes}")
        if copy_folder(folder_name, egnyte_token):
            print(f"Folder '{folder_name}' created successfully.")
            update_proposal_in_acumatica(proposal['ProposalNbr'], folder_name)
        else:
            print(f"Failed to create folder '{folder_name}'.")
    else:
        print(f"Folder '{folder_name}' already exists.")

def save_to_csv(proposals, filename='proposals.csv'):
    # Optional: export the latest proposals snapshot to CSV for audits/debugging
    headers = ['ProposalNbr', 'ProjectID', 'Department', 'Status', 'Amount', 'CompanyName', 'BusinessAccount', 'Date', 'ProjectDescription', 'Branch']
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()

        for proposal in proposals:
            writer.writerow({
                'ProposalNbr': proposal['ProposalNbr'],
                'ProjectID': proposal['ProjectID'],
                'Department': proposal['Department'],
                'Status': proposal['Status'],
                'Amount': proposal['Amount'],
                'CompanyName': proposal['CompanyName'],
                'BusinessAccount': proposal['BusinessAccount'],
                'Date': proposal['Date'],
                'ProjectDescription': proposal['ProjectDescription'],
                'Branch': proposal['Branch']
            })
'''
def main(egnyte_token): # One-Time Version  
    # Single-pass run (kept commented in your source). Useful for manual invocations.
    token, session_id = authenticate_acumatica()
    if not token or not session_id:
        print("Failed to authenticate with Acumatica.")
        return

    print("Retrieving proposal data...")
    proposals_info = retrieve_proposal_data(token, session_id)

    print("Data retrieval complete, preparing to process proposals...")
    print(f"Total proposals fetched: {len(proposals_info)}")

    print("Waiting a bit before starting to avoid rate limit...")
    time.sleep(5)

    prepared_proposals = [
        proposal for proposal in proposals_info
        if proposal['Status'].lower() == 'prepared'
        and proposal['ProposalNbr'].startswith(current_year_prefix)
        and proposal['Branch'] == 'BPL'
    ]
    print(f"Total prepared proposals: {len(prepared_proposals)}")

    for proposal in prepared_proposals:
        try:
            process_proposal(proposal, egnyte_token)
        except Exception as e:
            print(f"Error processing proposal {proposal.get('ProposalNbr', 'Unknown')}: {e}")
            continue

    if token and session_id:
        logoff_acumatica(token, session_id)

    print("Finished processing all proposals.")

if __name__ == "__main__":
    try:
        egnyte_token = authenticate_egnyte()
        main(egnyte_token)
    except KeyboardInterrupt:
        print("Script execution manually stopped.")'''

def main(egnyte_token):  # Perpetual Version
    # Production mode: endless loop with 10-minute intervals between iterations
    while True:
        try:
            print("Starting a new iteration...")
            
            # Refresh Egnyte token periodically
            egnyte_token = authenticate_egnyte()
            if not egnyte_token:
                print("Failed to authenticate with Egnyte.")
                time.sleep(600)  # Wait 10 minutes before retrying
                continue

            token, session_id = authenticate_acumatica()
            if not token or not session_id:
                print("Failed to authenticate with Acumatica.")
                time.sleep(600)  # Wait 10 minutes before retrying
                continue

            print("Retrieving proposal data...")
            proposals_info = retrieve_proposal_data(token, session_id)

            print("Data retrieval complete, preparing to process proposals...")
            print(f"Total proposals fetched: {len(proposals_info)}")

            print("Waiting a bit before starting to avoid rate limit...")
            time.sleep(5)

            # Business filters: prepared, correct year prefix, BPL branch, not already marked created
            prepared_proposals = [
                proposal for proposal in proposals_info
                if proposal['Status'].lower() == 'prepared'
                and proposal['ProposalNbr'].startswith(current_year_prefix)
                and proposal['Branch'] == 'BPL'
                and proposal['EgnyteFolder'] != 'Created'
            ]
            print(f"Total prepared proposals: {len(prepared_proposals)}")

            for proposal in prepared_proposals:
                try:
                    process_proposal(proposal, egnyte_token)
                except Exception as e:
                    print(f"Error processing proposal {proposal.get('ProposalNbr', 'Unknown')}: {e}")
                    continue

            if token and session_id:
                logoff_acumatica(token, session_id)

            print("Finished processing all proposals in this iteration.")
            print("Waiting for 10 minutes before starting the next iteration...")
            time.sleep(600)  # Wait for 10 minutes (600 seconds)

        except Exception as e:
            # Top-level guard: avoid killing the loop on unexpected exceptions
            print(f"An error occurred in the main loop: {e}")
            print("Waiting for 10 minutes before retrying...")
            time.sleep(600)
            print("Retrying now...")

if __name__ == "__main__":
    try:
        egnyte_token = authenticate_egnyte()
        main(egnyte_token)
    except KeyboardInterrupt:
        print("Script execution manually stopped.")
