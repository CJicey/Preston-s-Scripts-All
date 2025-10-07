import logging
import smtplib
from email.message import EmailMessage
from concurrent.futures import ThreadPoolExecutor
import time
from functools import partial
from requests.exceptions import ReadTimeout, HTTPError
import re
import requests
from urllib.parse import quote
import os
from dotenv import load_dotenv, find_dotenv
import csv
import json
from csv import DictWriter

# ---------------------------
# Environment + global config
# ---------------------------

# Load secrets and configuration values from config.env (if present) into environment variables.
# find_dotenv helps locate the file even if the working directory changes.
load_dotenv(find_dotenv(filename='config.env'))

# Mapping of "condition set" -> "template folder name" populated from TemplateGuide.csv at runtime.
template_mapping = {}

# Base URLs and paths for Egnyte + Acumatica APIs and local files.
EGNYTE_API_BASE = "https://bennettpless.egnyte.com/pubapi/v1"
CHECK_FOLDER_BASE_PATH = "Projects/2025"  # Egnyte path under /Shared where project folders live
TEMPLATE_FOLDER_BASE_PATH = "Team Member Resources/IT/ProjectFolderTemplates"
TEMPLATE_GUIDE = "C:/Scripts/Regular Projects/TemplateGuide.csv"  # CSV that maps business rules to templates
BASE_URL = "https://bennett-pless.acumatica.com"
LOGOFF_ENDPOINT = "/entity/auth/logout"

# Token cache files (simple JSON files on disk) to avoid re-authing on every call.
ACUMATICA_TOKEN_CACHE_FILE = 'acumatica_token_cache.json'
TOKEN_CACHE_FILE = 'egnyte_token_cache.json'

# Basic rotating log to file (append). Adjust level to DEBUG for deeper troubleshooting.
logging.basicConfig(
    filename='application.log',
    filemode='a',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# A short-hand used to filter "current year" projects (e.g., "25.XX.XXX").
current_year_prefix = '25'

# Toggle to control whether we PATCH/PUT back to Acumatica when changes occur.
update_acumatica = True

# Department code (middle token in project ID) -> Department folder name on Egnyte/Lucid.
department_mapping = {
    "00": "25.00.000 - Atlanta",
    "01": "25.01.000 - Corporate - Admin",
    "02": "25.02.000 - Nashville",
    "03": "25.03.000 - Florida",
    "04": "25.04.000 - Knoxville",
    "05": "25.05.000 - Chattanooga",
    "06": "25.06.000 - Sarasota",
    "07": "25.07.000 - Charlotte",
    "08": "25.08.000 - Raleigh",
    "09": "25.09.000 - Loudoun",
}


def authenticate():
    """
    Authenticate to Acumatica using resource-owner-password (ROP) flow.
    Caches access_token + ASP.NET session cookie on disk with an expiration timestamp.
    Returns: (access_token, session_id)
    Raises: Exception on non-200 responses.
    """
    # Use cached token if not expired
    if os.path.exists(ACUMATICA_TOKEN_CACHE_FILE):
        with open(ACUMATICA_TOKEN_CACHE_FILE, 'r') as file:
            token_data = json.load(file)
            expiration_time = token_data.get('expiration_time')
            if expiration_time and time.time() < expiration_time:
                return token_data['access_token'], token_data['session_id']

    # Pull client/app credentials + user creds from environment (.env)
    base_url = "https://bennett-pless.acumatica.com/identity/connect/token"
    client_id = os.getenv("ACUMATICA_CLIENT_ID")
    client_secret = os.getenv("ACUMATICA_CLIENT_SECRET")
    username = os.getenv("ACUMATICA_USERNAME")
    password = os.getenv("ACUMATICA_PASSWORD")

    # ROP grant parameters
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

    # Exchange credentials for token
    response = requests.post(base_url, data=payload, headers=headers)
    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data['access_token']
        expires_in = token_data['expires_in']  # seconds
        # Acumatica also sends an ASP.NET session cookie we need to include on entity calls
        session_id = response.cookies.get('ASP.NET_SessionId')

        # Subtract ~60s to refresh slightly before hard expiry
        expiration_time = time.time() + expires_in - 60

        # Cache on disk so subsequent calls can reuse token until expiry
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
    Log off Acumatica (invalidate session). Also clears the local cache if success.
    Returns True on success; raises on failure.
    """
    headers = {
        'Authorization': f'Bearer {token}',
        'Cookie': f'ASP.NET_SessionId={session_id}'
    }
    response = requests.post(f"{BASE_URL}{LOGOFF_ENDPOINT}", headers=headers)
    if response.status_code == 204:
        # Remove token cache proactively (force next call to re-auth)
        if os.path.exists(ACUMATICA_TOKEN_CACHE_FILE):
            os.remove(ACUMATICA_TOKEN_CACHE_FILE)
        return True
    else:
        raise Exception(f"Error {response.status_code} logging off: {response.text}")


def load_token_from_file():
    """
    Load Egnyte token cache (if present).
    Returns dict or empty dict if missing/invalid.
    """
    try:
        with open(TOKEN_CACHE_FILE, 'r') as file:
            token_data = json.load(file)
            return token_data
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_token_to_file(token_data):
    """Persist Egnyte token cache to disk."""
    with open(TOKEN_CACHE_FILE, 'w') as file:
        json.dump(token_data, file)


def authenticate_egnyte(retry_count=0):
    """
    Authenticate to Egnyte using password grant, with basic retry on 429 rate limiting.
    Returns access_token string, or None on failure.
    """
    current_time = time.time()
    token_data = load_token_from_file()

    # Reuse cached token if it's younger than ~3500 seconds (~58m)
    if token_data.get('access_token') and (current_time - token_data.get('timestamp', 0) < 3500):
        print("Using cached token...")
        return token_data['access_token']

    # Hard cap on recursive retries to avoid infinite loops
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
        save_token_to_file(token_data)
        print("Token refreshed and cached.")
        return token_data['access_token']
    except requests.exceptions.HTTPError as http_err:
        # Handle explicit rate limiting hint if provided
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


def retrieve_project_data(max_retries=5, delay=10):  # Production Version
    """
    Pull the list of projects from Acumatica (entity endpoint), flatten needed fields,
    save a CSV snapshot, and return a simplified list with key attributes used downstream.
    Retries on empty-response/parse issues up to max_retries.
    """
    attempts = 0
    while attempts < max_retries:
        token, session_id = authenticate()

        # Select key fields + include custom attributes; adjust the DAC/endpoint as your instance requires.
        api_url = (
            "https://bennett-pless.acumatica.com/entity/BPAcumaticav2/22.200.001/"
            "Project?$select=ProjectID,ClientCustomerID,ProjectIDClient,ProjectIDProjectName,Status,Branch,"
            "EgnyteFolder,MasterProjectName,MasterProjectTrue,AddToExistingSeries,DepartmentDescription,"
            "ContractAmount,Market,SubMarket,ServiceType&$expand=Attributes"
        )
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Cookie": f"ASP.NET_SessionId={session_id}"
        }

        response = requests.get(api_url, headers=headers)
        print(f"Status Code: {response.status_code}")

        # Some infra issues return 200 with empty body; handle that explicitly
        if not response.text.strip():
            print("No content received in response. Retrying...")
            attempts += 1
            time.sleep(delay)
            continue

        if response.status_code == 200:
            try:
                projects_data = response.json()
                # Depending on Acumatica config, the payload might be { "value": [...] } or bare array
                projects_list = projects_data.get('value', []) if isinstance(projects_data, dict) else projects_data
                project_folder_names = []

                for project in projects_list:
                    # Extract with .get(...).get('value', default) to avoid KeyError for missing fields
                    project_id = project.get('ProjectID', {}).get('value', 'UNKNOWN_PROJECT_ID')
                    client_customer_id = project.get('ClientCustomerID', {}).get('value', 'No Client Customer ID')
                    project_id_client = project.get('ProjectIDClient', {}).get('value', 'No Project ID Client')
                    project_name = project.get('ProjectIDProjectName', {}).get('value', 'NO_PROJECT_NAME')
                    status = project.get('Status', {}).get('value', 'UNKNOWN')
                    branch = project.get('Branch', {}).get('value', 'UNKNOWN')
                    egnyte_folder_status = project.get('EgnyteFolder', {}).get('value', 'UNKNOWN')
                    master_project_name = project.get('MasterProjectName', {}).get('value', 'NOT_AVAILABLE')
                    master_project_true = str(project.get('MasterProjectTrue', {}).get('value', 'False'))
                    add_to_existing_series = str(project.get('AddToExistingSeries', {}).get('value', 'False'))
                    department_description = project.get('DepartmentDescription', {}).get('value', 'UNKNOWN')

                    # ContractAmount might be null/empty; convert gracefully to float, else 0
                    contract_amount_value = project.get('ContractAmount', {}).get('value')
                    contract_amount = float(contract_amount_value) if contract_amount_value not in [None, '', 'unknown'] else 0

                    market = project.get('Market', {}).get('value', 'UNKNOWN')
                    sub_market = project.get('SubMarket', {}).get('value', 'UNKNOWN')
                    service_type = project.get('ServiceType', {}).get('value', 'UNKNOWN')

                    # Build folder name: master vs regular differs slightly
                    if master_project_true:
                        folder_name = f"{project_id} - {project_name}"
                    else:
                        folder_name = f"{project_id} - {client_customer_id} - {project_name}"

                    project_folder_names.append({
                        'ProjectID': project_id,
                        'folder_name': folder_name,
                        'department_description': department_description,
                        'contract_amount': contract_amount,
                        'market': market,
                        'sub_market': sub_market,
                        'service_type': service_type,
                        'status': status,
                        'branch': branch,
                        'egnyte_folder_status': egnyte_folder_status,
                        'master_project_true': master_project_true,
                        'master_project_name': master_project_name,
                        'add_to_existing_series': add_to_existing_series,
                        'project_id_client': project_id_client,
                        'project_name': project_name,
                        'client_customer_id': client_customer_id,
                    })

                # Persist raw snapshot for auditing/diagnostics
                save_to_csv(projects_list)
                return project_folder_names

            except json.JSONDecodeError as e:
                # JSON-bad responses sometimes happen; retry after delay
                print(f"JSON decoding failed: {e}")
                print(f"JSON decoding failed: {e}")
                print("Response Text:", response.text)
                attempts += 1
                time.sleep(delay)
                continue
        else:
            print(f"Failed to retrieve project data: {response.status_code}")
            print(f"Response Text: {response.text}")
            attempts += 1
            time.sleep(delay)
            continue

    print("Maximum retries exceeded. No data retrieved.")
    return []


# ---------------------------
# Series project handling (child under master)
# ---------------------------

def process_series_project(project_attributes, egnyte_token, department_mapping):
    """
    Create a series/child project folder beneath an existing master project folder,
    after verifying the master exists. Chooses a template for series projects.
    """
    print(f"Processing series project: {project_attributes['ProjectID']}")
    print(f"Processing series project: {project_attributes['ProjectID']}")

    series_project_id = project_attributes['ProjectID']
    series_project_client_id = project_attributes['ProjectClientID']
    series_project_name = project_attributes['ProjectIDProjectName']

    # Retrieve master project to derive customer/name (display)
    master_project_id = project_attributes['MasterProjectName']
    master_project_info = get_master_project_details(master_project_id)
    if master_project_info:
        master_project_client_id = master_project_info.get('ClientCustomerID', 'No Client Customer ID')
        master_project_name = master_project_info.get('ProjectName', 'NO_PROJECT_NAME')
    else:
        print(f"Could not retrieve details for master project {master_project_id}")

    department_code = project_attributes['department_code']
    department = project_attributes['department_folder']

    # Pick a template for series projects (special case for telecom)
    if project_attributes['market'] == 'Infrastructure' and project_attributes['sub_market'] == 'Telecom Structures':
        template_folder_name = 'Niche Tower Project Template'
    else:
        template_folder_name = 'Series Projects Child'

    project_attributes['template_folder_name'] = template_folder_name

    # Build Egnyte paths under /Shared/Projects/2025/...
    master_project_folder_path = f"{department}/{master_project_id} - {master_project_name}"
    series_project_folder_path = f"{master_project_folder_path}/{series_project_id} - {series_project_client_id} - {series_project_name}"

    print(f"Series Project ID: {series_project_id}, Client ID: {series_project_client_id}, Project Name: {series_project_name}")
    print(f"Master Project ID: {master_project_id}, Master Client ID: {master_project_client_id}, Master Project Name: {master_project_name}, Department: {department}, Department Code: {department_code}")
    print(f"Series Project ID: {series_project_id}, Client ID: {series_project_client_id}, Project Name: {series_project_name}")
    print(f"Master Project ID: {master_project_id}, Master Client ID: {master_project_client_id}, Master Project Name: {master_project_name}, Department: {department}, Department Code: {department_code}")

    # Master must exist first
    if not check_folder_exists(egnyte_token, master_project_folder_path, master_project_id):
        print(f"Master project folder {master_project_folder_path} does not exist.")
        return

    # Skip if child already exists
    if check_folder_exists(egnyte_token, series_project_folder_path, series_project_id):
        print(f"Series project folder {series_project_folder_path} already exists.")
        return

    project_attributes['copy_destination_path'] = f"{CHECK_FOLDER_BASE_PATH}/{series_project_folder_path}"

    # Copy the template into the destination child folder
    if copy_folder(series_project_folder_path, project_attributes, egnyte_token):
        print(f"Series project folder {series_project_folder_path} successfully created under {master_project_folder_path}.")
        if update_acumatica:
            update_project_in_acumatica(series_project_id, 'created')
    else:
        print(f"Failed to create series project folder {series_project_folder_path} under {master_project_folder_path}.")


def get_master_project_details(master_project_id):
    """
    Lookup a single master project in Acumatica by ProjectID and return a subset of fields.
    On success: dict with ClientCustomerID, ProjectName, DepartmentDescription, Status
    On failure: None
    """
    token, session_id = authenticate()
    print(f"Retrieving master project details for {master_project_id}")

    # Encode the ProjectID safely for OData $filter
    encoded_project_id = requests.utils.quote(master_project_id)
    api_url = (
        "https://bennett-pless.acumatica.com/entity/BPAcumaticav2/22.200.001/"
        f"Project?$select=ProjectID,ClientCustomerID,ProjectIDClient,ProjectIDProjectName,Status,Branch,EgnyteFolder,"
        "MasterProjectName,MasterProjectTrue,AddToExistingSeries,DepartmentDescription,ContractAmount,Market,SubMarket,ServiceType"
        f"&$expand=Attributes&$filter=ProjectID eq '{encoded_project_id}'"
    )

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Cookie": f"ASP.NET_SessionId={session_id}"
    }

    response = requests.get(api_url, headers=headers)
    if response.status_code == 200:
        try:
            project_data = response.json()
            # Depending on endpoint config, you might get a list or a {value:[...]}
            if project_data and isinstance(project_data, list):
                project = project_data[0]
                project_details = {
                    'ClientCustomerID': project.get('ClientCustomerID', {}).get('value', 'No Client Customer ID'),
                    'ProjectName': project.get('ProjectIDProjectName', {}).get('value', 'NO_PROJECT_NAME'),
                    'DepartmentDescription': project.get('DepartmentDescription', {}).get('value', 'UNKNOWN'),
                    'Status': project.get('Status', {}).get('value', 'UNKNOWN'),
                }
                logoff_acumatica(token, session_id)
                return project_details
            else:
                print(f"No project found with ProjectID {master_project_id}")
                logoff_acumatica(token, session_id)
                return None
        except json.JSONDecodeError:
            print(f"Failed to decode JSON response for master project {master_project_id}")
            logoff_acumatica(token, session_id)
            return None
    else:
        print(f"Failed to retrieve master project details for {master_project_id} with status code {response.status_code}")
        logoff_acumatica(token, session_id)
        return None


def process_BPL_project(project, egnyte_token):
    """
    Placeholder for BPL branch-specific logic (if BPL projects need a separate flow).
    """
    print(f"Processing BPL project: {project['folder_name']}")


def save_to_csv(projects, filename='projects.csv'):
    """
    Save a CSV snapshot of the raw Acumatica projects payload (selected fields).
    Useful for audits and quick offline filtering.
    """
    headers = [
        'ProjectID', 'Status', 'Branch', 'ProjectTemplateID', 'Customer', 'Description',
        'MasterProjectTrue', 'EgnyteFolder', 'AddToExistingSeries', 'MasterProjectName'
    ]

    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()

        for project in projects:
            # Some fields might be native booleans/objects; stringify consistently
            master_project_true_value = str(project.get('MasterProjectTrue', 'False'))
            egnyte_folder_status = project.get('EgnyteFolder', 'Unknown')
            add_to_existing_series_value = str(project.get('AddToExistingSeries', 'False'))

            writer.writerow({
                'ProjectID': project.get('ProjectID', {}).get('value', ''),
                'Status': project.get('Status', {}).get('value', ''),
                'Branch': project.get('Branch', {}).get('value', ''),
                'ProjectTemplateID': project.get('ProjectTemplateID', {}).get('value', ''),
                'Customer': project.get('Customer', {}).get('value', ''),
                'Description': project.get('Description', {}).get('value', ''),
                'MasterProjectName': project.get('MasterProjectName', {}).get('value', ''),
                'MasterProjectTrue': master_project_true_value,
                'EgnyteFolder': egnyte_folder_status,
                'AddToExistingSeries': add_to_existing_series_value,
            })


def export_projects_to_csv():
    """
    Simple wrapper to pull projects and export them to CSV immediately.
    """
    projects = retrieve_project_data()
    if projects:
        save_to_csv(projects)


def check_folder_exists(egnyte_token, folder_name, project_id):
    """
    Check if a given /Shared/Projects/2025/{folder_name} path already exists in Egnyte.
    On 200: exists (and optionally push status back to Acumatica).
    On 404: does not exist.
    On other codes: return None (error).
    """
    check_url = f"{EGNYTE_API_BASE}/fs/shared/{CHECK_FOLDER_BASE_PATH}/{folder_name}"
    headers = {
        "Authorization": f"Bearer {egnyte_token}"
    }
    print(f"API call for checking folder existence: {check_url}")
    response = requests.get(check_url, headers=headers)
    print(f"Checking if folder exists: {check_url}")
    if response.status_code == 200:
        print(f"Folder '{folder_name}' already exists.")
        if update_acumatica:
            update_project_in_acumatica(project_id, 'created')
        return True
    elif response.status_code == 404:
        return False
    else:
        print(f"Failed to check folder: {response.status_code}")
        print(f"Response Text: {response.text}")
        return None


def update_project_in_acumatica(project_id, egnyte_folder_status):
    """
    Update the project's EgnyteFolder status field in Acumatica.
    Uses a PUT to the same entity endpoint filtered by ProjectID.
    """
    token, session_id = authenticate()
    if not token or not session_id:
        print(f"Failed to authenticate with Acumatica for updating project {project_id}.")
        return

    api_url = (
        "https://bennett-pless.acumatica.com/entity/BPAcumaticav2/22.200.001/"
        f"Project?$select=ProjectID,ClientCustomerID,ProjectIDClient,ProjectIDProjectName,Status,Branch,EgnyteFolder,"
        "MasterProjectName,MasterProjectTrue,AddToExistingSeries,DepartmentDescription,ContractAmount,Market,SubMarket,ServiceType"
        f"&$expand=Attributes&$filter=ProjectID eq '{project_id}'"
    )
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Cookie": f"ASP.NET_SessionId={session_id}"
    }
    # "CD" (Created) appears to be the target status value
    data = {
        "EgnyteFolder": {"value": "CD"}
    }
    response = requests.put(api_url, headers=headers, json=data)
    if response.status_code == 200:
        print(f"Successfully updated project {project_id} in Acumatica with egnyte_folder status: {egnyte_folder_status}")
    else:
        print(f"Failed to update project {project_id} in Acumatica. Status code: {response.status_code}")

    logoff_acumatica(token, session_id)


def load_template_mapping(template_guide_path='C:/Scripts/Regular Projects/TemplateGuide.csv'):
    """
    Load the business rules -> template name mapping from the TemplateGuide CSV.
    Populates the global 'template_mapping' dict.
    """
    global template_mapping
    with open(template_guide_path, mode='r', encoding='utf-8-sig') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            condition_set = row['ConditionSet'].strip()
            template_name = row['TemplateName'].strip()
            template_mapping[condition_set] = template_name


def determine_template_path(project_attributes):
    """
    Given a project's attributes (department, market, service type, etc.), decide which
    template "ConditionSet" applies, then map to an actual template folder name using
    the loaded TemplateGuide. Falls back to 'Null/(empty)' if no rule matches.
    """
    global template_mapping
    if not template_mapping:
        load_template_mapping()

    # Business rules in priority order
    if project_attributes['master_project_true'] == 'True':
        selected_template = 'ConditionSet11'
    elif project_attributes['add_to_existing_series'] == 'True':
        selected_template = 'ConditionSet12'
    elif project_attributes['department_description'] == 'Raleigh':
        selected_template = 'ConditionSet1'
    elif project_attributes['department_description'] == 'Charlotte':
        selected_template = 'ConditionSet2'
    elif project_attributes['department_description'] == 'Loudoun' and project_attributes['sub_market'] in ['High-End Residential', 'Housing']:
        selected_template = 'ConditionSet14'
    elif project_attributes['contract_amount'] < 7500.00:
        selected_template = 'ConditionSet3'
    elif (project_attributes['market'] == 'Infrastructure' and project_attributes['sub_market'] == 'Telecom Structures'):
        selected_template = 'ConditionSet4'
    elif (project_attributes['service_type'] == 'Adaptive Re-Use' and project_attributes['contract_amount'] > 7500.00):
        selected_template = 'ConditionSet5'
    elif (project_attributes['service_type'] == 'Existing - Analysis/Reinf' and project_attributes['contract_amount'] > 7500.00):
        selected_template = 'ConditionSet6'
    elif (project_attributes['service_type'] == 'Existing - Assessment/Repair' and project_attributes['contract_amount'] > 7500.00):
        selected_template = 'ConditionSet7'
    elif (project_attributes['service_type'] == 'New - Design-Bid-Build' and project_attributes['contract_amount'] > 7500.00):
        selected_template = 'ConditionSet8'
    elif (project_attributes['service_type'] == 'New - Design-Build' and project_attributes['contract_amount'] > 7500.00):
        selected_template = 'ConditionSet9'
    else:
        selected_template = 'Null/(empty)'

    # Return the actual folder name referenced by Egnyte copy API
    return template_mapping.get(selected_template, template_mapping['Null/(empty)'])


def remove_trailing_period(folder_name: str) -> str:
    """
    Egnyte forbids trailing spaces/periods in file/folder names.
    If found, remove the trailing '.' and return a sanitized name.
    """
    if folder_name.endswith('.'):
        return folder_name[:-1]
    return folder_name


def copy_folder(folder_name, project_attributes, egnyte_token, sanitizing_retried=False):
    """
    Copy a template folder into /Shared/Projects/2025/{folder_name} on Egnyte.
    Template may be explicit (Series/Niche) or chosen via determine_template_path().
    Retries once on timeouts and once on specific "trailing period" error by sanitizing name.
    Returns True on success, False on failure.
    """
    # Allow an explicit override placed into project_attributes by series logic
    template_folder_name = project_attributes.get('template_folder_name')
    if template_folder_name == 'Series Projects Child':
        source_path = "/Shared/Team Member Resources/IT/ProjectFolderTemplates/Series Projects Child"
        print("Selected Template Folder Name: Series Projects Child")
    elif template_folder_name == 'Niche Tower Project Template':
        source_path = "/Shared/Team Member Resources/IT/ProjectFolderTemplates/Niche Tower Project Template"
        print("Selected Template Folder Name: Niche Tower Project Template")
    else:
        # Resolve from rule engine (TemplateGuide)
        template_folder_name = determine_template_path(project_attributes)
        source_path = f"/Shared/{TEMPLATE_FOLDER_BASE_PATH}/{template_folder_name}"
        print(f"Selected Template Folder Name: {template_folder_name}")

    destination_path = f"/Shared/{CHECK_FOLDER_BASE_PATH}/{folder_name}"
    print(f"Attempting to copy from source: {source_path}")
    print(f"Attempting to copy to destination: {destination_path}")

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

    attempt_count = 0
    max_attempts = 2
    timeout = 30  # seconds per request

    while attempt_count < max_attempts:
        try:
            response = requests.post(copy_url, headers=headers, json=data, timeout=timeout)
            response.raise_for_status()
            print(f"Folder copied successfully to {folder_name}")
            return True
        except requests.ReadTimeout:
            # Transient network issue; try again once
            print(f"Attempt {attempt_count + 1} timed out. Trying again...")
            attempt_count += 1
        except requests.HTTPError as http_err:
            # Detect Egnyte's invalid name error and attempt a one-time sanitize+retry
            if ("File names cannot contain leading or trailing spaces" in response.text
                and not sanitizing_retried):
                sanitized_name = remove_trailing_period(folder_name)
                if sanitized_name != folder_name:
                    print(f"Removing trailing period: '{folder_name}' -> '{sanitized_name}' and retrying.")
                    return copy_folder(sanitized_name, project_attributes, egnyte_token, sanitizing_retried=True)

            print(f"HTTP error occurred: {http_err} - {response.text}")
            send_email_alert(folder_name)
            return False
        except Exception as err:
            # Catch-all for unexpected situations: alert + exit
            print(f"An error occurred: {err}")
            send_email_alert(folder_name)
            return False

    print(f"Failed to copy folder after {max_attempts} attempts.")
    send_email_alert(folder_name)
    return False


def rename_folder(egnyte_token, old_path, new_folder_name):
    """
    Rename (move) a folder in Egnyte by posting an action=move to the fs API.
    old_path: full path under /pubapi/v1/fs (e.g., 'shared/Projects/2025/...')
    new_folder_name: new name or destination path (per Egnyte API semantics)
    """
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


# Track which projects already triggered an email (avoid alert spam)
emailed_projects = set()


def send_email_alert(folder_name):
    """
    Send a single alert email per folder_name when folder creation fails.
    Uses SMTP creds from environment (.env).
    """
    if folder_name in emailed_projects:
        return

    msg = EmailMessage()
    msg['Subject'] = "A Project Folder Failed to Process"
    msg['From'] = os.getenv("SENDER_EMAIL")
    msg['To'] = "support@bennett-pless.com"
    msg.set_content(f"A Project Folder has failed to process.\n\nFolder Name: {folder_name}")

    try:
        smtp_server = os.getenv("SMTP_SERVER")
        smtp_port = int(os.getenv("SMTP_PORT", 587))
        smtp_password = os.getenv("SMTP_PASSWORD")

        with smtplib.SMTP(smtp_server, smtp_port) as smtp:
            smtp.starttls()
            smtp.login(msg['From'], smtp_password)
            smtp.send_message(msg)

        print(f"Alert email sent for folder '{folder_name}'.")
    except Exception as e:
        print(f"Failed to send email alert for folder '{folder_name}': {e}")

    emailed_projects.add(folder_name)


def process_project(project, egnyte_token):
    """
    Decide the destination folder for a single project and create it if needed.
    - BPL branch projects are routed to a separate handler (placeholder).
    - For others, compute department path and call copy_folder if missing.
    """
    print(f"Processing project: {project['folder_name']}")

    # Optional separate path for BPL branch
    if project.get('branch', '').upper() == 'BPL':
        process_BPL_project(project, egnyte_token)
        return

    # Parse department code from ProjectID (format looks like '25.08.123')
    project_id_parts = project['ProjectID'].split('.')
    department_code = project_id_parts[1] if len(project_id_parts) > 1 else 'Unknown'
    department_folder = department_mapping.get(department_code, 'Unknown')

    # Master projects omit the client ID segment in folder naming
    if project['master_project_true'] == 'True':
        folder_name = f"{department_folder}/{project['folder_name']}"
    else:
        folder_name = f"{department_folder}/{project['ProjectID']} - {project['client_customer_id']} - {project['project_name']}"

    # Normalize 'True'/'False'/bools to a boolean for logic
    add_to_existing_series = str(project.get('add_to_existing_series', '')).lower() == 'true'

    # Pack attributes used by the template-rule engine
    project_attributes = {
        'ProjectID': project['ProjectID'],
        'ClientCustomerID': project.get('client_customer_id', 'UNKNOWN'),
        'ProjectName': project.get('project_name', 'UNKNOWN'),
        'MasterProjectName': project.get('master_project_name', 'UNKNOWN'),
        'folder_name': folder_name,
        'department_description': project['department_description'],
        'contract_amount': project['contract_amount'],
        'market': project['market'],
        'sub_market': project['sub_market'],
        'service_type': project['service_type'],
        'master_project_true': project['master_project_true'],
        'add_to_existing_series': add_to_existing_series,
        'department_code': department_code,
        'department_folder': department_folder,
        'ProjectClientID': project.get('project_id_client', 'UNKNOWN'),
        'ProjectIDProjectName': project.get('project_name', 'UNKNOWN'),
    }

    # Series child creation vs normal project creation
    if add_to_existing_series:
        process_series_project(project_attributes, egnyte_token, department_mapping)
    elif not check_folder_exists(egnyte_token, folder_name, project['ProjectID']):
        # Only copy if it doesn't already exist
        if copy_folder(folder_name, project_attributes, egnyte_token):
            print(f"Folder '{folder_name}' created successfully.")
            if update_acumatica:
                update_project_in_acumatica(project['ProjectID'], 'created')
        else:
            print(f"Failed to create folder '{folder_name}'.")
    else:
        print(f"Folder '{folder_name}' already exists.")


# ---------------------------
# Main loop: continuous polling every 5 minutes
# ---------------------------

def main():
    """
    Production loop:
      - Auth to Acumatica and Egnyte
      - Pull projects
      - Filter to current-year, active, not already 'created' in Egnyte, non-BPL
      - Process each project (create or skip)
      - Log off; sleep 5 minutes; repeat
    """
    while True:
        try:
            print("Starting a new iteration...")
            token, session_id = authenticate()
            if not token or not session_id:
                print("Failed to authenticate with Acumatica.")
                time.sleep(300)  # Wait 5 minutes before retrying
                continue

            projects_info = retrieve_project_data()

            # Filter to actionable projects
            active_projects = [
                project for project in projects_info
                if project['status'].lower() == 'active'
                and project.get('ProjectID', '').startswith(current_year_prefix)
                and project.get('egnyte_folder_status', '').lower() != 'created'
                and project.get('branch', '').upper() != 'BPL'
            ]

            egnyte_token = authenticate_egnyte()
            if not egnyte_token:
                print("Failed to authenticate with Egnyte.")
                if token and session_id:
                    logoff_acumatica(token, session_id)
                time.sleep(300)  # Wait 5 minutes before retrying
                continue

            # Process eligible projects one-by-one (stateless per project)
            for project in active_projects:
                try:
                    process_project(project, egnyte_token)
                except Exception as e:
                    # Continue with next project on failure
                    print(f"Error processing project {project.get('folder_name', 'Unknown')}: {e}")
                    continue

            # Close Acumatica session after each iteration to be polite to the server
            if token and session_id:
                logoff_acumatica(token, session_id)

            print("Finished processing all projects in this iteration.")
            print("Waiting for 5 minutes before starting the next iteration...")
            time.sleep(300)  # 5 minutes
        except Exception as e:
            # Catch-all for the loop. Sleep before re-trying iteration.
            print(f"An error occurred in the main loop: {e}")
            print("Waiting for 5 minutes before retrying...")
            time.sleep(300)


if __name__ == "__main__":
    try:
        # Pre-load the template mapping so the first copy call has it ready.
        load_template_mapping(TEMPLATE_GUIDE)
        main()
    except KeyboardInterrupt:
        print("Script execution manually stopped.")
