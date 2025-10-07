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

# ---------------------------
# Environment + logging setup
# ---------------------------

# Load environment variables from config.env (if present) into process env.
# find_dotenv lets this work even if the working directory changes.
load_dotenv(find_dotenv(filename='config.env'))

# Determine a stable, absolute log file path next to this script.
script_dir = os.path.dirname(os.path.abspath(__file__))
log_file_path = os.path.join(script_dir, 'proposals.log')

# Append logs to proposals.log with timestamps + level + logger name.
logging.basicConfig(
    filename=log_file_path,
    filemode='a',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# ---------------------------
# Constants / global config
# ---------------------------

# Only process proposals with numbers like "P.25xxxxx"
current_year_prefix = 'P.25'

# Egnyte destination base for proposals (under /Shared)
CHECK_FOLDER_BASE_PATH = "/proposals/2025"

# Where the proposal templates live (under /Shared)
TEMPLATE_FOLDER_BASE_PATH = "Team Member Resources/IT/ProjectFolderTemplates"

# CSV used to map business rules -> template names (for proposals)
TEMPLATE_GUIDE = "c:/Scripts/Regular Proposals/ProposalTemplateGuide.csv"

# Egnyte REST base
EGNYTE_API_BASE = "https://bennettpless.egnyte.com/pubapi/v1"

# Where we cache Egnyte OAuth tokens locally
TOKEN_CACHE_FILE = 'egnyte_token_cache.json'

# Acumatica host + logout endpoint
BASE_URL = "https://bennett-pless.acumatica.com"
LOGOFF_ENDPOINT = "/entity/auth/logout"

# Where we cache Acumatica token/session locally
ACUMATICA_TOKEN_CACHE_FILE = 'acumatica_token_cache.json'

# In-memory holder (unused in most flows since we persist to file too)
EGNYTE_TOKEN_CACHE = {
    'access_token': None,
    'timestamp': None
}


def load_template_mapping(template_guide_path='c:/Scripts/Regular Proposals/ProposalTemplateGuide.csv'):
    """
    Load proposal template rules from CSV into a global dict named template_mapping.
    The CSV must have columns: ConditionSet, TemplateName.
    """
    global template_mapping
    template_mapping = {}
    try:
        with open(template_guide_path, mode='r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                # Optional debug prints for verifying CSV parsing
                print(f"CSV Row: {row}")
                condition_set = row['ConditionSet'].strip()
                template_name = row['TemplateName'].strip()
                print(f"Loading mapping for proposals: {condition_set} -> {template_name}")
                template_mapping[condition_set] = template_name
    except FileNotFoundError:
        print(f"Template guide file not found: {template_guide_path}")
    except Exception as e:
        print(f"Error loading template mapping from {template_guide_path}: {e}")


# Pre-load mapping at import time so determine_template_path has data on first call.
load_template_mapping('c:/Scripts/Regular Proposals/ProposalTemplateGuide.csv')


def authenticate_acumatica():
    """
    Authenticate against Acumatica using ROPC (resource owner password credentials).
    Returns a tuple (access_token, session_id).
    Uses a small JSON file cache with an expiration timestamp to avoid re-authing too often.
    """
    # Try cached token first
    if os.path.exists(ACUMATICA_TOKEN_CACHE_FILE):
        with open(ACUMATICA_TOKEN_CACHE_FILE, 'r') as file:
            token_data = json.load(file)
            expiration_time = token_data.get('expiration_time')
            if expiration_time and time.time() < expiration_time:
                return token_data['access_token'], token_data['session_id']

    # Pull credentials from environment variables (.env)
    base_url = "https://bennett-pless.acumatica.com/identity/connect/token"
    client_id = os.getenv("ACUMATICA_CLIENT_ID")
    client_secret = os.getenv("ACUMATICA_CLIENT_SECRET")
    username = os.getenv("ACUMATICA_USERNAME")
    password = os.getenv("ACUMATICA_PASSWORD")

    # ROPC payload
    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'username': username,
        'password': password,
        'grant_type': 'password',
        'scope': 'api'
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    # Exchange credentials for token + ASP.NET session cookie
    response = requests.post(base_url, data=payload, headers=headers)
    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data['access_token']
        expires_in = token_data['expires_in']  # seconds until expiry
        session_id = response.cookies.get('ASP.NET_SessionId')

        # Subtract a minute to refresh proactively
        expiration_time = time.time() + expires_in - 60

        # Cache token/session locally
        token_data = {
            'access_token': access_token,
            'session_id': session_id,
            'expiration_time': expiration_time
        }
        with open(ACUMATICA_TOKEN_CACHE_FILE, 'w') as file:
            json.dump(token_data, file)

        return access_token, session_id
    else:
        raise Exception(f"Failed to authenticate with Acumatica. Status code: {response.status_code}")


def logoff_acumatica(token, session_id):
    """
    Log off Acumatica and remove the cached token file.
    Returns True on success, else raises an Exception.
    """
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


def load_egnyte_token_from_file():
    """
    Load Egnyte OAuth token cache (JSON). Return {} if missing or invalid.
    """
    try:
        with open(TOKEN_CACHE_FILE, 'r') as file:
            token_data = json.load(file)
            return token_data
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_egnyte_token_to_file(token_data):
    """Persist Egnyte token + timestamp to local JSON cache."""
    with open(TOKEN_CACHE_FILE, 'w') as file:
        json.dump(token_data, file)


def authenticate_egnyte(retry_count=0):
    """
    Authenticate to Egnyte (password grant) with basic retry handling for 429 rate limiting.
    Returns access_token string or None on failure.
    """
    current_time = time.time()
    token_data = load_egnyte_token_from_file()

    # Use cached token if it's still fresh (~< 58 minutes old)
    if token_data.get('access_token') and (current_time - token_data.get('timestamp', 0) < 3500):
        print("Using cached token...")
        return token_data['access_token']

    if retry_count >= 3:
        print("Maximum authentication retries exceeded.")
        return None

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
        # Honor server-provided backoff if present
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
    """
    Check if /Shared/proposals/2025/{folder_name} exists in Egnyte.
    If it exists (200), update the proposal in Acumatica to mark EgnyteFolder as Created.
    Returns True if exists, False if 404, None for other errors.
    """
    check_url = f"{EGNYTE_API_BASE}/fs/shared/{CHECK_FOLDER_BASE_PATH}/{folder_name}"
    headers = {"Authorization": f"Bearer {egnyte_token}"}

    response = requests.get(check_url, headers=headers)
    print(f"Checking if folder exists: {check_url}")
    if response.status_code == 200:
        update_proposal_in_acumatica(proposal_nbr, folder_name)
        return True
    elif response.status_code == 404:
        return False
    else:
        print(f"Failed to check folder: {response.status_code}")
        print(f"Response Text: {response.text}")
        return None


def update_proposal_in_acumatica(proposal_nbr, folder_name):
    """
    Mark the proposal's EgnyteFolder field as 'Created' in Acumatica.
    Looks up by ProposalNbr first, then PUTs with the same endpoint to update.
    """
    token, session_id = authenticate_acumatica()
    if not token or not session_id:
        print(f"Failed to authenticate with Acumatica for updating proposal {proposal_nbr}.")
        return

    api_url = (
        f"https://bennett-pless.acumatica.com/entity/BPAcumaticav2/22.200.001/"
        f"Proposals?$filter=ProposalNbr eq '{proposal_nbr}'&$select=EgnyteFolder"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Cookie": f"ASP.NET_SessionId={session_id}"
    }

    # Retrieve proposal by number
    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        try:
            proposal_data = response.json()
        except json.JSONDecodeError as e:
            print(f"DEBUG: JSON decoding error for ProposalNbr {proposal_nbr}: {e}")
            proposal_data = []

        print(f"DEBUG: Retrieved {len(proposal_data)} proposal(s) for ProposalNbr {proposal_nbr}.")
        if len(proposal_data) > 1:
            # Rare case: duplicates; log IDs for investigation
            ids = [p.get("id", "No ID") for p in proposal_data]
            print(f"DEBUG: Multiple proposals found for ProposalNbr {proposal_nbr}: {ids}")
            print(f"DEBUG: Full response data: {proposal_data}")

        if proposal_data:
            proposal_id = proposal_data[0]["id"]
            data = {
                "id": proposal_id,
                "EgnyteFolder": {"value": "Created"}
            }
            print(f"DEBUG: Attempting to update proposal with ID {proposal_id} using data: {data}")
            put_response = requests.put(api_url, headers=headers, json=data)
            if put_response.status_code == 200:
                print(f"Successfully updated proposal {proposal_nbr} in Acumatica with Egnyte folder status: 'Created'")
            else:
                print(f"Failed to update proposal {proposal_nbr} in Acumatica. Status code: {put_response.status_code}")
                print(f"Response content: {put_response.content}")
                print(f"Request data: {data}")
        else:
            print(f"Proposal {proposal_nbr} not found in Acumatica.")
    else:
        print(f"Failed to retrieve proposal {proposal_nbr} from Acumatica. Status code: {response.status_code}")
        print(f"Response content: {response.content}")

    # Close session after we finish
    logoff_acumatica(token, session_id)


def copy_folder(folder_name, egnyte_token):
    """
    Copy the default proposal template folder into /Shared/proposals/2025/{folder_name}.
    Returns True on success, False on exception.
    """
    # NOTE: Currently always uses "P24-XXXX - Proposal Example" template.
    source_path = f"/Shared/{TEMPLATE_FOLDER_BASE_PATH}/P24-XXXX - Proposal Example"
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
        # print(f"Folder '{folder_name}' created successfully.")
        return True
    except Exception as e:
        print(f"Failed to create folder '{folder_name}': {e}")
        return False


def rename_folder(egnyte_token, old_path, new_folder_name):
    """
    Rename/move a folder in Egnyte via fs action=move.
    old_path: path relative to /pubapi/v1/fs (e.g., 'shared/proposals/2025/...')
    new_folder_name: new basename or new full destination path per Egnyte API.
    """
    url = f"https://bennettpless.egnyte.com/pubapi/v1/fs/{old_path}"
    headers = {
        "Authorization": f"Bearer {egnyte_token}",
        "Content-Type": "application/json"
    }
    data = {"action": "move", "destination": f"{new_folder_name}"}

    response = requests.post(url, headers=headers, json=data)

    if response.status_code in [200, 201]:
        print(f"Folder renamed successfully to {new_folder_name}")
        return True
    else:
        print(f"Failed to rename folder. Status Code: {response.status_code}, Response: {response.text}")
        return False


def set_permissions():
    """
    Placeholder for future Egnyte permissioning logic (ACLs/shares).
    """
    pass


def load_template_mapping(template_guide_path='c:/Scripts/Regular Proposals/ProposalTemplateGuide.csv'):
    """
    (Duplicate definition preserved from original.)
    Loads proposal ConditionSet->TemplateName mapping into global template_mapping.
    """
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
    """
    Decide which template to use for a proposal based on attributes.
    Right now, defaults to ConditionSet1 or falls back to the example template.
    """
    global template_mapping
    if not template_mapping:
        load_template_mapping()

    selected_template = template_mapping.get('ConditionSet1', 'P24-XXXX - Proposal Example')

    print(
        f"Proposal '{proposal_attributes['ProposalNbr']}', Attributes: {proposal_attributes}, "
        f"Template Selected: '{selected_template}'"
    )

    return selected_template


def retrieve_proposal_data(token, session_id, max_retries=5, delay=10):
    """
    Pull the list of proposals from Acumatica.
    Returns a list of dicts with normalized fields used downstream.
    Retries on transient JSON/empty issues.
    """
    api_url = "https://bennett-pless.acumatica.com/entity/BPAcumaticav2/22.200.001/Proposals"
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
            try:
                proposals_data = response.json() if raw_response else []
                formatted_proposals = []
                unique_proposal_numbers = set()

                for proposal in proposals_data:
                    proposal_number = proposal.get('ProposalNbr', {}).get('value', '')
                    # Enforce uniqueness by ProposalNbr (API may return dup records depending on filters)
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
                # Temporary parse issue; back off and retry
                print(f"JSON decoding failed: {e}")
                attempts += 1
                time.sleep(delay)
                continue
        else:
            # Non-200; log error body for debugging and retry
            print(f"Failed to retrieve proposal data: {response.status_code}")
            print(f"Response Text: {response.text}")
            attempts += 1
            time.sleep(delay)
            continue

    print("Maximum retries exceeded. No data retrieved.")
    # Be nice and log off the session if we still have it in scope
    logoff_acumatica(token, session_id)
    return []


def process_proposal(proposal, egnyte_token):
    """
    Build the destination folder name for a proposal and ensure it exists in Egnyte.
    If missing, copy the template and then update Acumatica to mark it Created.
    """
    print(f"Processing proposal: {proposal['ProposalNbr']} - {proposal['CompanyName']}")

    # Standard proposal folder format: {Nbr} - {BusinessAccount} - {Description}
    folder_name = f"{proposal['ProposalNbr']} - {proposal['BusinessAccount']} - {proposal['ProjectDescription']}"

    # Attributes that could feed determine_template_path in the future
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

    # Skip creation if it already exists (will also mark as Created in Acumatica)
    if not check_folder_exists(egnyte_token, folder_name, proposal['ProposalNbr']):
        print(f"Debug: Proposal Attributes: {proposal_attributes}")
        if copy_folder(folder_name, egnyte_token):
            print(f"Folder '{folder_name}' created successfully.")
            logging.info(f"Successfully created Egnyte folder: {folder_name}")
            update_proposal_in_acumatica(proposal['ProposalNbr'], folder_name)
        else:
            print(f"Failed to create folder '{folder_name}'.")
    else:
        print(f"Folder '{folder_name}' already exists.")


def save_to_csv(proposals, filename='proposals.csv'):
    """
    Write a CSV snapshot of proposals fetched from Acumatica (selected fields).
    Helpful for audits and offline filtering/debugging.
    """
    headers = [
        'ProposalNbr', 'ProjectID', 'Department', 'Status', 'Amount', 'CompanyName',
        'BusinessAccount', 'Date', 'ProjectDescription', 'Branch', 'EgnyteFolder'
    ]

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
                'Branch': proposal['Branch'],
                'EgnyteFolder': proposal['EgnyteFolder']
            })


# ---------------------------
# Main loop (perpetual version)
# ---------------------------

def main(egnyte_token):
    """
    Continuous worker:
      1) Auth to Acumatica
      2) Fetch proposals
      3) Filter to current-year prepared/draft, non-BPL, not already Created
      4) Ensure Egnyte folder exists (create if missing), update Acumatica
      5) Log off + sleep, repeat
    """
    while True:
        try:
            print("Starting a new iteration...")
            token, session_id = authenticate_acumatica()
            if not token or not session_id:
                print("Failed to authenticate with Acumatica.")
                time.sleep(300)  # 5 minutes
                continue

            print("Retrieving proposal data...")
            proposals_info = retrieve_proposal_data(token, session_id)

            print("Data retrieval complete, preparing to process proposals...")
            print(f"Total proposals fetched: {len(proposals_info)}")

            # Small pause to be respectful to APIs
            print("Waiting a bit before starting to avoid rate limit...")
            time.sleep(5)

            # Filter to proposals ready for folder creation
            prepared_proposals = [
                proposal for proposal in proposals_info
                if proposal['Status'].lower() in ['prepared', 'draft']
                and proposal['ProposalNbr'].startswith(current_year_prefix)
                and proposal['Branch'] != 'BPL'
                and proposal['EgnyteFolder'] != 'Created'
            ]
            print(f"Total prepared proposals: {len(prepared_proposals)}")

            # Create/verify folders one-by-one
            for proposal in prepared_proposals:
                try:
                    process_proposal(proposal, egnyte_token)
                except Exception as e:
                    print(f"Error processing proposal {proposal.get('ProposalNbr', 'Unknown')}: {e}")
                    continue

            # Close Acumatica session each loop
            if token and session_id:
                logoff_acumatica(token, session_id)

            print("Finished processing all proposals in this iteration.")
            print("Waiting for 10 minutes before starting the next iteration...")
            time.sleep(600)  # 10 minutes
        except Exception as e:
            # Outer safety net so the loop never dies silently
            print(f"An error occurred in the main loop: {e}")
            print("Waiting for 10 minutes before retrying...")
            time.sleep(600)


if __name__ == "__main__":
    try:
        # Get Egnyte token up front; if it fails we still enter main, which could retry later.
        egnyte_token = authenticate_egnyte()
        main(egnyte_token)
    except KeyboardInterrupt:
        print("Script execution manually stopped.")
