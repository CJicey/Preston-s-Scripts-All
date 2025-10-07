import logging
import time
import requests
import os
import json
from requests.exceptions import ReadTimeout, HTTPError
from urllib.parse import quote
from dotenv import load_dotenv, find_dotenv

###############################################################################
# Load environment variables
###############################################################################
load_dotenv(find_dotenv(filename='c:/scripts/BPL Projects/config.env'))

EGNYTE_API_BASE = "https://bennettpless.egnyte.com/pubapi/v1"
CHECK_FOLDER_BASE_PATH = "Bennett & Pless Leicht/projects/2025"
BASE_URL = "https://bennett-pless.acumatica.com"
LOGOFF_ENDPOINT = "/entity/auth/logout"

ACUMATICA_TOKEN_CACHE_FILE = 'acumatica_token_cache.json'
EGNYTE_TOKEN_CACHE_FILE = 'egnyte_token_cache.json'

logging.basicConfig(
    filename='application.log',
    filemode='a',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

current_year_prefix = '25'

###############################################################################
# Acumatica Authentication
###############################################################################
def authenticate_acumatica():
    """
    Authenticates against Acumatica, returning (access_token, session_id).
    Uses local file-based caching to avoid unnecessary re-auth.
    Mirrors your non-BPL script logic.
    """
    print("Authenticating with Acumatica...")
    if os.path.exists(ACUMATICA_TOKEN_CACHE_FILE):
        with open(ACUMATICA_TOKEN_CACHE_FILE, 'r') as file:
            token_data = json.load(file)
            expiration_time = token_data.get('expiration_time')
            if expiration_time and time.time() < expiration_time:
                print("Acumatica token cache still valid.")
                return token_data['access_token'], token_data['session_id']

    token_url = "https://bennett-pless.acumatica.com/identity/connect/token"
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
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}

    resp = requests.post(token_url, data=payload, headers=headers)
    if resp.status_code == 200:
        token_info = resp.json()
        access_token = token_info['access_token']
        expires_in = token_info['expires_in']
        session_id = resp.cookies.get('ASP.NET_SessionId')

        # Subtract 60s as a buffer
        expiration_time = time.time() + expires_in - 60
        token_data = {
            'access_token': access_token,
            'session_id': session_id,
            'expiration_time': expiration_time
        }
        with open(ACUMATICA_TOKEN_CACHE_FILE, 'w') as file:
            json.dump(token_data, file)

        print("Acumatica authentication successful.")
        return access_token, session_id
    else:
        raise Exception(
            f"Failed to authenticate with Acumatica (status: {resp.status_code}, text={resp.text})."
        )

def logoff_acumatica(token, session_id, max_retries=3, backoff=5):
    """
    Logs off from Acumatica, removing the cached token file upon success.
    Retries on ReadTimeout up to `max_retries` times, with exponential backoff.
    """
    print("Logging off from Acumatica...")
    headers = {
        'Authorization': f'Bearer {token}',
        'Cookie': f'ASP.NET_SessionId={session_id}'
    }

    for attempt in range(1, max_retries + 1):
        try:
            # Use a 30s timeout
            response = requests.post(f"{BASE_URL}{LOGOFF_ENDPOINT}", headers=headers, timeout=30)
            if response.status_code == 204:
                if os.path.exists(ACUMATICA_TOKEN_CACHE_FILE):
                    os.remove(ACUMATICA_TOKEN_CACHE_FILE)
                print("Successfully logged off from Acumatica.")
                return True
            else:
                print(f"Warning: logoff responded with {response.status_code}, text={response.text}")
                return False

        except requests.exceptions.ReadTimeout:
            print(f"Logoff request timed out on attempt {attempt}. Retrying...")
            time.sleep(backoff * attempt)  # exponential backoff
        except requests.RequestException as e:
            # Catch any other request-related errors
            print(f"Error during logoff (attempt {attempt}): {e}")
            return False

    print("Exceeded max retries trying to log off from Acumatica.")
    return False

###############################################################################
# Egnyte Authentication
###############################################################################
def load_egnyte_token_from_file():
    try:
        with open(EGNYTE_TOKEN_CACHE_FILE, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def save_egnyte_token_to_file(token_data):
    with open(EGNYTE_TOKEN_CACHE_FILE, 'w') as file:
        json.dump(token_data, file)

def authenticate_egnyte(retry_count=0):
    """
    Authenticates with Egnyte, caching the token in a local file.
    Reuses if 'fresh' enough.
    """
    print("Authenticating with Egnyte...")
    current_time = time.time()
    token_data = load_egnyte_token_from_file()

    # If an existing token is still "fresh" (less than ~3500s), reuse it
    if token_data.get('access_token') and (current_time - token_data.get('timestamp', 0) < 3500):
        print("Using cached Egnyte token.")
        return token_data['access_token']

    if retry_count >= 3:
        print("Egnyte auth: max retries exceeded.")
        return None

    print("Pausing briefly to avoid immediate rate-limit issues...")
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
        resp = requests.post(url, data=payload)
        resp.raise_for_status()
        token_info = resp.json()
        new_data = {
            'access_token': token_info['access_token'],
            'timestamp': current_time
        }
        save_egnyte_token_to_file(new_data)
        print("Egnyte token refreshed and cached.")
        return new_data['access_token']
    except requests.HTTPError as http_err:
        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", 60))
            print(f"Egnyte rate limit exceeded. Retry after {retry_after} seconds.")
            time.sleep(retry_after)
            return authenticate_egnyte(retry_count + 1)
        else:
            print(f"Egnyte HTTP error: {http_err}. Response text={resp.text}")
    except Exception as ex:
        print(f"Egnyte auth error: {ex}")

    return None

###############################################################################
# Egnyte Folder Checking & Copy
###############################################################################
def check_folder_exists(egnyte_token, folder_name):
    """
    Checks if Egnyte folder /Shared/Bennett & Pless Leicht/projects/2025/{folder_name} exists.
    Returns True/False or None on error.
    """
    check_url = f"{EGNYTE_API_BASE}/fs/shared/{CHECK_FOLDER_BASE_PATH}/{folder_name}"
    headers = {"Authorization": f"Bearer {egnyte_token}"}

    print(f"Checking Egnyte folder existence: {check_url}")
    resp = requests.get(check_url, headers=headers)
    if resp.status_code == 200:
        return True
    elif resp.status_code == 404:
        return False
    else:
        print(f"Error checking folder: status={resp.status_code}, text={resp.text}")
        return None

def copy_folder_to_egnyte(egnyte_token, folder_name):
    """
    Copies template folder into the final Egnyte location if not found.
    The template for BPL projects is BPL New Project.
    """
    source_path = "/Shared/Team Member Resources/IT/ProjectFolderTemplates/BPL New Project"
    destination_path = f"/Shared/{CHECK_FOLDER_BASE_PATH}/{folder_name}"

    print(f"Copying from: {source_path}")
    print(f"Copying to:   {destination_path}")

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
        resp = requests.post(copy_url, headers=headers, json=data, timeout=30)
        resp.raise_for_status()
        print(f"Folder copied successfully to '{folder_name}'.")
        return True
    except requests.RequestException as e:
        print(f"Failed to copy folder '{folder_name}': {e}")
        return False

###############################################################################
# Retrieve & Update Projects in Acumatica
###############################################################################
def retrieve_project_data(acumatica_token, acumatica_session_id, max_retries=5, delay=10):
    """
    Retrieves all BPL projects from Acumatica that meet the conditions:
     - Branch eq 'BPL'
     - Status eq 'Active'
     - ProjectID starts with '25'
     - EgnyteFolder eq null or EgnyteFolder eq 'Pending'
    Acumatica may return an array or a dict with 'value'. We handle both.
    """
    print("Retrieving BPL project data from Acumatica...")
    attempts = 0
    api_url = (
        f"{BASE_URL}/entity/BPAcumaticav2/22.200.001/Project"
        f"?$select=ProjectID,ClientCustomerID,ProjectIDProjectName,EgnyteFolder,Status"
        f"&$filter=Branch eq 'BPL' and Status eq 'Active'"
        f" and startswith(ProjectID, '{current_year_prefix}')"
        f" and (EgnyteFolder eq null or EgnyteFolder eq 'Pending')"
    )

    headers = {
        "Authorization": f"Bearer {acumatica_token}",
        "Content-Type": "application/json",
        "Cookie": f"ASP.NET_SessionId={acumatica_session_id}"
    }

    while attempts < max_retries:
        print(f"GET -> {api_url}")
        try:
            resp = requests.get(api_url, headers=headers, timeout=30)
            print(f"Acumatica response status: {resp.status_code}")
            if resp.status_code == 200:
                resp_data = resp.json()
                # Acumatica might return a list or a dict with "value"
                if isinstance(resp_data, list):
                    projects_list = resp_data
                elif isinstance(resp_data, dict):
                    projects_list = resp_data.get('value', [])
                else:
                    print("Warning: Acumatica returned unexpected JSON structure.")
                    projects_list = []

                print(f"Number of BPL projects found: {len(projects_list)}")

                results = []
                for proj in projects_list:
                    project_id = proj.get('ProjectID', {}).get('value', 'UNKNOWN')
                    client_id = proj.get('ClientCustomerID', {}).get('value', 'NoClientID')
                    project_name = proj.get('ProjectIDProjectName', {}).get('value', 'NoName')
                    egnyte_val = proj.get('EgnyteFolder', {}).get('value', 'UNKNOWN')
                    status_val = proj.get('Status', {}).get('value', 'UNKNOWN')

                    folder_name = f"{project_id} - {client_id} - {project_name}"
                    print(f" -> Found project: {project_id}, folder='{folder_name}', EgnyteFolder={egnyte_val}")

                    results.append({
                        'ProjectID': project_id,
                        'folder_name': folder_name,
                        'client_customer_id': client_id,
                        'project_name': project_name,
                        'egnyte_folder_status': egnyte_val,
                        'status': status_val
                    })
                return results
            else:
                print(f"Unexpected response {resp.status_code}: {resp.text}")
                attempts += 1
                time.sleep(delay)
        except requests.RequestException as e:
            print(f"Error retrieving BPL projects: {e}")
            attempts += 1
            time.sleep(delay)

    print("Failed to retrieve BPL projects after multiple attempts.")
    return []

def update_project_in_acumatica(acumatica_token, acumatica_session_id, project_id):
    """
    Uses the same approach as your non-BPL script:
     - PUT /Project?$filter=ProjectID eq '{project_id}'
       to set EgnyteFolder = "CD".
    This avoids requiring ProjectID to be the 'real' key in Acumatica.
    """
    print(f"Updating EgnyteFolder for ProjectID={project_id} in Acumatica...")

    # The non-BPL approach does a PUT on the entity with a filter
    url = (
        f"{BASE_URL}/entity/BPAcumaticav2/22.200.001/Project"
        f"?$select=ProjectID,ClientCustomerID,ProjectIDClient,ProjectIDProjectName,"
        f"Status,Branch,EgnyteFolder,MasterProjectName,MasterProjectTrue,"
        f"AddToExistingSeries,DepartmentDescription,ContractAmount,Market,"
        f"SubMarket,ServiceType&$expand=Attributes"
        f"&$filter=ProjectID eq '{project_id}'"
    )

    headers = {
        "Authorization": f"Bearer {acumatica_token}",
        "Content-Type": "application/json",
        "Cookie": f"ASP.NET_SessionId={acumatica_session_id}"
    }
    payload = {
        "EgnyteFolder": {"value": "CD"}
    }

    try:
        resp = requests.put(url, headers=headers, json=payload, timeout=30)
        print(f"PUT {url} => status {resp.status_code}")
        print(f"Response text: {resp.text}")

        if resp.status_code == 200:
            print(f"Successfully updated Project {project_id} in Acumatica (EgnyteFolder=CD).")
            return True
        else:
            print(f"Failed to update project {project_id}. Status={resp.status_code}")
            return False
    except requests.RequestException as ex:
        print(f"Exception updating project {project_id}: {ex}")
        return False

###############################################################################
# Main Per-Project Processing
###############################################################################
def process_single_bpl_project(project_dict, egnyte_token, acumatica_token, acumatica_session_id):
    """
    - Check Egnyte for the project folder
    - If not found, copy the BPL template
    - Update the project in Acumatica to reflect EgnyteFolder=CD
    """
    project_id = project_dict['ProjectID']
    folder_name = project_dict['folder_name']
    print(f"\nProcessing BPL project: {project_id} => '{folder_name}'")

    folder_exists = check_folder_exists(egnyte_token, folder_name)
    if folder_exists is None:
        print(f"Unable to confirm folder existence for '{folder_name}', skipping Acumatica update.")
        return

    if not folder_exists:
        print(f"Folder '{folder_name}' not found in Egnyte; copying template...")
        copy_success = copy_folder_to_egnyte(egnyte_token, folder_name)
        if copy_success:
            print(f"Folder '{folder_name}' created successfully in Egnyte.")
        else:
            print(f"Failed to create folder '{folder_name}'; skipping Acumatica update.")
            return
    else:
        print(f"Folder '{folder_name}' already exists in Egnyte.")

    # Now update the project's EgnyteFolder in Acumatica
    update_project_in_acumatica(acumatica_token, acumatica_session_id, project_id)

###############################################################################
# Main Loop
###############################################################################
def main():
    """
    Repeats every 15 minutes. Steps:
     1) Auth to Egnyte
     2) Auth to Acumatica
     3) Retrieve BPL projects needing Egnyte folder
     4) For each project, copy if needed & update Acumatica
     5) Log off Acumatica
     6) Wait 15 minutes
    """
    while True:
        print("\n=== Starting BPL Projects Iteration ===")

        # Step 1: Egnyte
        egnyte_token = authenticate_egnyte()
        if not egnyte_token:
            print("Egnyte auth failed. Retrying in 15 minutes...")
            time.sleep(900)
            continue

        # Step 2: Acumatica
        try:
            acumatica_token, acumatica_session_id = authenticate_acumatica()
        except Exception as e:
            print(f"Failed to authenticate Acumatica: {e}")
            print("Retrying in 15 minutes...")
            time.sleep(900)
            continue

        # Step 3: Retrieve BPL projects
        projects = retrieve_project_data(acumatica_token, acumatica_session_id)
        if not projects:
            print("No BPL projects found to process. Logging off and waiting 15 min.")
            logoff_acumatica(acumatica_token, acumatica_session_id)
            time.sleep(900)
            continue

        # Step 4: Process each
        for proj in projects:
            try:
                process_single_bpl_project(
                    proj,
                    egnyte_token,
                    acumatica_token,
                    acumatica_session_id
                )
            except Exception as ex:
                print(f"Error processing project {proj.get('ProjectID','Unknown')}: {ex}")

        # Step 5: Log off Acumatica (won't cause script termination if it fails)
        print("Done with this iteration, logging off Acumatica now.")
        logoff_acumatica(acumatica_token, acumatica_session_id)

        # Step 6: Sleep 15 minutes
        print("\n=== Sleeping 15 minutes before next iteration... ===")
        time.sleep(900)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScript execution manually stopped.")