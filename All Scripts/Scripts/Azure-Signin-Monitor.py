# =============================================================================
# AzureSignInMonitor – richly documented reference implementation
# =============================================================================
# What this script does (high level)
# ----------------------------------
# • Periodically fetches successful Azure AD sign‑in events from Microsoft Graph.
# • Builds per‑user behavioral baselines ("whitelists") from history:
# – Common sign‑in locations (city/state/country) by frequency threshold
# – Typical working hours (5th–95th percentile window)
# • Detects suspicious events in new polls:
# – Unusual location (not in a user’s safe list)
# – Unusual time (outside typical hours ± configurable buffer)
# – (Optional) Impossible travel between consecutive sign‑ins
# • Suppresses alerts from trusted contexts:
# – Enrolled/managed devices (Graph deviceId present)
# – Whitelisted device fingerprints (deterministic hash of traits)
# – Whitelisted IPs (e.g., office egress)
# • Produces CSV reports, emails them, and can post summaries to a Teams channel.
#
# Why these choices?
# ------------------
# • App‑only auth (client credentials) is reliable for service daemons.
# • Sliding‑window client rate‑limiter + server Retry‑After handling avoids 429s.
# • CSV + JSON state makes the system transparent, diff‑able, and easy to debug.
# • "Training mode" creates baselines first to reduce noise once monitoring starts.
#
# Files created alongside the script
# ---------------------------------
# ./Data/login_history.csv – flattened sign‑in history (append‑only)
# ./Data/last_fetch.json – most recent poll end time (UTC ISO)
# ./Data/user_whitelists.json – per‑user baselines (locations/hours)
# ./Data/device_fingerprint_whitelist.json– known‑good device fingerprints
# ./Data/excluded_alerts_log.csv – alerts suppressed by exemptions
# ./Data/training_data_suspicious_report_YYYYMMDD_HHMMSS.csv – training check
# ./Polling Reports/suspicious_signin_report_<start>_to_<end>.csv – per poll
#
# Operational modes
# -----------------
# • Training mode (TRAINING_MODE=True): builds baselines from N historical days.
# Can optionally reuse an existing login_history.csv (no Graph calls).
# • Standard mode: every polling_period_minutes, fetch the delta since last poll
# (with a safety lookback buffer), analyze, and notify.
#
# Extensibility notes
# -------------------
# • To add more checks (e.g., ASN risk, conditional access results), extend
# analyze_suspicious_logins with a new reason generator.
# • To support other messengers, mirror send_teams_notification.
# • To persist in a DB instead of CSV/JSON, adapt update_login_history/save_*.
# =============================================================================

import os
import json
import csv
import datetime
import time
import smtplib
import requests
import msal
import pytz
import signal
import sys
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from dotenv import load_dotenv
import uuid
import logging
import re
import secrets
import threading
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import math
from geopy.distance import geodesic
import traceback

# Create Data directory if it doesn't exist
os.makedirs("Data", exist_ok=True)
# Create Polling Reports directory if it doesn't exist
os.makedirs("Polling Reports", exist_ok=True)

class RateLimitManager:
    """Manages API request rate limits to avoid throttling"""
    
    def __init__(self, requests_per_minute=2000):
        self.requests_per_minute = requests_per_minute
        self.request_times = []
        self.lock = threading.Lock()
    
    def wait_if_needed(self):
        """Wait if we're approaching rate limits
        
        This implements a sliding window rate limiting approach
        """
        with self.lock:
            current_time = time.time()
            # Remove timestamps older than 1 minute
            one_minute_ago = current_time - 60
            self.request_times = [t for t in self.request_times if t > one_minute_ago]
            
            # If we're approaching the limit, wait
            if len(self.request_times) >= self.requests_per_minute * 0.8:  # 80% of limit
                # Calculate wait time - either wait until oldest request is outside window
                # or use exponential backoff based on how close we are to the limit
                if len(self.request_times) >= self.requests_per_minute * 0.95:  # 95% of limit
                    wait_time = max(5, 60 - (current_time - self.request_times[0]))
                    print(f"Approaching rate limit (95%). Waiting {wait_time:.2f} seconds...")
                else:
                    wait_time = max(1, 30 - (current_time - self.request_times[0]))
                    print(f"Approaching rate limit (80%). Waiting {wait_time:.2f} seconds...")
                
                time.sleep(wait_time)
                # Recursive call to check again after waiting
                return self.wait_if_needed()
                
            # Track this request
            self.request_times.append(current_time)
            return

class AzureSignInMonitor:
    """Monitors Azure AD sign-ins for suspicious activity

    Features:
    - Fetches sign-in logs from Microsoft Graph API
    - Creates user-specific whitelists of safe locations and work hours
    - Analyzes sign-ins for suspicious activity:
      - Logins from unusual locations
      - Logins at unusual hours
      - Impossible travel between logins
    - Device-based exclusion:
      - Exclude enrolled devices (with device_id) from alerts
      - Create and use fingerprint whitelist for trusted devices
      - Exclude sign-ins from whitelisted IP addresses (e.g., office locations)
    - Sends email notifications for suspicious logins
    - Supports Teams notifications
    - Training mode to build initial whitelist
    
    Configuration:
    - Use EXCLUDE_ENROLLED_DEVICES=True/False to toggle enrolled device exclusion
    - Use EXCLUDE_WHITELISTED_FINGERPRINTS=True/False to toggle fingerprint exclusion
    - Use EXCLUDE_WHITELISTED_IPS=True/False to toggle IP address exclusion
    - Use WHITELISTED_IPS=ip1,ip2,ip3 to specify trusted IP addresses
    - Use DEVICE_FINGERPRINT_MIN_LOGINS and DEVICE_FINGERPRINT_MIN_DAYS to set
      thresholds for adding fingerprints to the whitelist
    """
    def __init__(self, config_path="config.env"):
        """Initialize the monitor
        
        Args:
            config_path: Path to the config.env file
        """
        # Get the directory where the script is located
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Use path relative to script location for config
        self.config_path = os.path.join(self.script_dir, config_path)
        self.config = {}
        self.load_config()
        
        # Create Data directory if it doesn't exist
        os.makedirs(os.path.join(self.script_dir, "Data"), exist_ok=True)
        # Create Polling Reports directory if it doesn't exist
        os.makedirs(os.path.join(self.script_dir, "Polling Reports"), exist_ok=True)
        
        # Set file paths relative to script location
        self.login_history_path = os.path.join(self.script_dir, "Data", "login_history.csv")
        self.last_fetch_path = os.path.join(self.script_dir, "Data", "last_fetch.json")
        self.whitelist_path = os.path.join(self.script_dir, "Data", "user_whitelists.json")
        self.fingerprint_whitelist_path = os.path.join(self.script_dir, "Data", "device_fingerprint_whitelist.json")
        
        # Use timestamped filename for training report
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.training_report_path = os.path.join(self.script_dir, "Data", f"training_data_suspicious_report_{timestamp}.csv")
        
        # The suspicious_report_path will be set dynamically for each polling period
        self.suspicious_report_path = None
        
        self.excluded_alerts_log_path = os.path.join(self.script_dir, "Data", "excluded_alerts_log.csv")
        
        # Track authentication tokens
        self.auth_token = None
        self.token_expiry = None
        
        self.rate_limit_manager = RateLimitManager()
        self.shutdown_requested = False
        self.signal_handler_registered = False
        self.whitelists = {}
        
        # Track already reported suspicious logins to prevent duplicates
        self.reported_suspicious_ids = set()
        
        # Track whitelisted device fingerprints
        self.fingerprint_whitelist = set()
        
        # Track excluded alerts for logging
        self.excluded_alerts = []
        
        # Register signal handler for graceful shutdown
        if not self.signal_handler_registered:
            try:
                signal.signal(signal.SIGINT, self._handle_shutdown_signal)
                signal.signal(signal.SIGTERM, self._handle_shutdown_signal)
                self.signal_handler_registered = True
            except Exception as e:
                print(f"Warning: Could not register signal handler: {e}")
                print("Graceful shutdown via SIGINT/SIGTERM may not work.")
        
    def _setup_signal_handlers(self):
        """Set up signal handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self._handle_shutdown_signal)
        signal.signal(signal.SIGTERM, self._handle_shutdown_signal)
        
    def _handle_shutdown_signal(self, signum, frame):
        """Handle shutdown signals (SIGINT, SIGTERM)"""
        print("\nShutdown requested. Finishing current operations and exiting gracefully...")
        self.shutdown_requested = True
        
    def _check_for_shutdown(self):
        """Check if shutdown has been requested and exit if needed"""
        if self.shutdown_requested:
            print("Exiting due to shutdown request.")
            sys.exit(0)
        
    def load_config(self):
        """Load configuration from config.env file"""
        load_dotenv(self.config_path)
        
        self.config = {
            # Azure credentials
            "client_id": os.getenv("AZURE_CLIENT_ID"),
            "client_secret": os.getenv("AZURE_CLIENT_SECRET"),
            "tenant_id": os.getenv("AZURE_TENANT_ID"),
            
            # Email settings
            "smtp_server": os.getenv("SMTP_SERVER"),
            "smtp_port": int(os.getenv("SMTP_PORT", 587)),
            "smtp_username": os.getenv("SMTP_USERNAME"),
            "smtp_password": os.getenv("SMTP_PASSWORD"),
            "sender_email": os.getenv("SENDER_EMAIL"),
            "recipient_email": os.getenv("RECIPIENT_EMAIL"),
            
            # Email notification toggles
            "send_training_emails": os.getenv("SEND_TRAINING_EMAILS", "True").lower() == "true",
            "send_monitoring_emails": os.getenv("SEND_MONITORING_EMAILS", "True").lower() == "true",
            
            # Teams notification settings
            "teams_notification": os.getenv("TEAMS_NOTIFICATION", "False").lower() == "true",
            "teams_webhook_url": os.getenv("TEAMS_WEBHOOK_URL", ""),
            "teams_group_id": os.getenv("TEAMS_GROUP_ID", "5a5635d2-5972-46db-9ce1-cffe9eb1bc1f"),
            "teams_channel_id": os.getenv("TEAMS_CHANNEL_ID", "19:f18df18135de41fdb12f47cb382ba0eb@thread.skype"),
            "teams_tenant_id": os.getenv("TEAMS_TENANT_ID", "ad2f4227-1c9a-427a-8b9c-8f3e3c7243cc"),
            
            # Operational settings
            "training_mode": os.getenv("TRAINING_MODE", "False").lower() == "true",
            "training_days": int(os.getenv("TRAINING_DAYS", 30)),
            "use_existing_login_history_csv": os.getenv("USE_EXISTING_LOGIN_HISTORY_CSV", "False").lower() == "true",
            "polling_period_minutes": int(os.getenv("POLLING_PERIOD_MINUTES", 5)),
            
            # Analysis settings
            "allowed_countries": os.getenv("ALLOWED_COUNTRIES", "US").split(","),
            "international_users": os.getenv("INTERNATIONAL_USERS", "").split(","),
            "location_frequency_threshold": float(os.getenv("LOCATION_FREQUENCY_THRESHOLD", 0.1)),
            "time_outlier_threshold_hours": float(os.getenv("TIME_OUTLIER_THRESHOLD_HOURS", 2.0)),
            
            # Impossible travel settings
            "max_travel_speed_mph": float(os.getenv("MAX_TRAVEL_SPEED_MPH", 900)),
            "min_travel_distance_miles": float(os.getenv("MIN_TRAVEL_DISTANCE_MILES", 50)),
            "impossible_travel_exempt_apps": os.getenv("IMPOSSIBLE_TRAVEL_EXEMPT_APPS", "").split(","),
            "unusual_location_exempt_apps": os.getenv("UNUSUAL_LOCATION_EXEMPT_APPS", "").split(","),
            
            # Check toggles
            "check_location": os.getenv("CHECK_LOCATION", "True").lower() == "true",
            "check_unusual_hours": os.getenv("CHECK_UNUSUAL_HOURS", "True").lower() == "true",
            "check_impossible_travel": os.getenv("CHECK_IMPOSSIBLE_TRAVEL", "False").lower() == "true",
            
            # Device exclusion settings
            "exclude_enrolled_devices": os.getenv("EXCLUDE_ENROLLED_DEVICES", "True").lower() == "true",
            "exclude_whitelisted_fingerprints": os.getenv("EXCLUDE_WHITELISTED_FINGERPRINTS", "True").lower() == "true",
            "device_fingerprint_min_logins": int(os.getenv("DEVICE_FINGERPRINT_MIN_LOGINS", 3)),
            "device_fingerprint_min_days": int(os.getenv("DEVICE_FINGERPRINT_MIN_DAYS", 7)),
            
            # IP address exclusion settings
            "exclude_whitelisted_ips": os.getenv("EXCLUDE_WHITELISTED_IPS", "True").lower() == "true",
            "whitelisted_ips": [ip.strip() for ip in os.getenv("WHITELISTED_IPS", "").split(",") if ip.strip()],
            
            # Retroactive whitelist update settings
            "retroactive_location_whitelist_updates": os.getenv("RETROACTIVE_LOCATION_WHITELIST_UPDATES", "True").lower() == "true",
            "retroactive_fingerprint_whitelist_updates": os.getenv("RETROACTIVE_FINGERPRINT_WHITELIST_UPDATES", "True").lower() == "true",
        }
    
    def get_auth_token(self, max_retries=3):
        """Get authentication token for Microsoft Graph API
        
        Args:
            max_retries: Maximum number of retries for token acquisition
            
        Returns:
            Access token string
        """
        # Check if we have a valid token
        current_time = time.time()
        if self.auth_token and current_time < self.token_expiry - 300:  # 5 min buffer
            return self.auth_token
            
        # Create MSAL app
        app = msal.ConfidentialClientApplication(
            self.config["client_id"],
            authority=f"https://login.microsoftonline.com/{self.config['tenant_id']}",
            client_credential=self.config["client_secret"]
        )
        
        # Get token with retry logic
        retry_count = 0
        base_wait_time = 5  # Start with 5 seconds
        
        while retry_count <= max_retries:
            try:
                # Get token
                scopes = ["https://graph.microsoft.com/.default"]
                result = app.acquire_token_for_client(scopes=scopes)
                
                if "access_token" in result:
                    self.auth_token = result["access_token"]
                    self.token_expiry = current_time + result["expires_in"]
                    return self.auth_token
                # Handle throttling or other token acquisition errors
                elif "error" in result and (result.get("error") == "throttled" or "429" in result.get("error_description", "")):
                    wait_time = base_wait_time * (2 ** retry_count)
                    wait_time = min(wait_time, 120)  # Cap at 2 minutes
                    print(f"Token acquisition throttled. Waiting {wait_time} seconds before retry. (Attempt {retry_count + 1}/{max_retries})")
                    time.sleep(wait_time)
                    retry_count += 1
                else:
                    error_msg = f"Authentication Error: {result.get('error')}: {result.get('error_description')}"
                    print(error_msg)
                    raise Exception(error_msg)
            except Exception as e:
                if retry_count < max_retries:
                    wait_time = base_wait_time * (2 ** retry_count)
                    print(f"Token acquisition error: {e}. Retrying in {wait_time} seconds. (Attempt {retry_count + 1}/{max_retries})")
                    time.sleep(wait_time)
                    retry_count += 1
                else:
                    raise Exception(f"Max retries exceeded during authentication: {e}")
        
        raise Exception("Failed to acquire access token after maximum retries")
    
    def fetch_signin_logs(self, start_time=None, end_time=None):
        """Fetch sign-in logs from Microsoft Graph API
        
        Args:
            start_time: Start time in ISO format (UTC)
            end_time: End time in ISO format (UTC)
            
        Returns:
            List of sign-in records
        """
        print("Fetching sign-in logs...")
        
        # Get authentication token
        token = self.get_auth_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        
        # Build filter for successful sign-ins only (status = 0)
        filter_query = "status/errorCode eq 0"
        
        # Add time filter if provided
        if start_time:
            filter_query += f" and createdDateTime ge {start_time}"
        if end_time:
            filter_query += f" and createdDateTime le {end_time}"
            
        # Build URL
        url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
        params = {
            "$filter": filter_query,
            # Don't use $select to ensure we get all fields
            "$top": 999  # Maximum allowed per request
        }
        
        all_sign_ins = []
        next_link = None
        
        # Initial request
        print(f"Sending request to {url} with params: {params}")
        try:
            response = self._make_throttle_aware_request(url, headers, params=params)
                
            data = response.json()
            
            # Debug the response
            if "value" in data and len(data["value"]) > 0:
                sample_record = data["value"][0]
                print(f"Sample sign-in record structure:")
                for key, value in sample_record.items():
                    if key == "location" and isinstance(value, dict):
                        print(f"  location: {value}")
                    elif key == "ipAddress":
                        print(f"  ipAddress: {value}")
                    else:
                        print(f"  {key}: [data]")
            
            all_sign_ins.extend(data.get("value", []))
            next_link = data.get("@odata.nextLink")
            
            # Handle pagination with interruption checks
            while next_link and not self.shutdown_requested:
                print(f"Fetching next page of sign-ins... (Total so far: {len(all_sign_ins)})")
                
                # Check for shutdown request
                self._check_for_shutdown()
                
                # Make request with throttling awareness
                response = self._make_throttle_aware_request(next_link, headers)
                
                data = response.json()
                all_sign_ins.extend(data.get("value", []))
                next_link = data.get("@odata.nextLink")
                
        except KeyboardInterrupt:
            print("\nFetch operation interrupted. Handling gracefully...")
            self.shutdown_requested = True
        except Exception as e:
            print(f"Error during fetch: {e}")
            raise
        
        print(f"Total sign-ins fetched: {len(all_sign_ins)}")
        return all_sign_ins
    
    def _make_throttle_aware_request(self, url, headers, params=None, max_retries=5):
        """Make a request to the Graph API with throttling awareness
        
        Args:
            url: Request URL
            headers: Request headers
            params: Optional request parameters
            max_retries: Maximum number of retries for throttled requests
            
        Returns:
            Response object
        """
        # Check rate limits before making the request
        self.rate_limit_manager.wait_if_needed()
        
        retry_count = 0
        base_wait_time = 5  # Start with 5 seconds
        
        while retry_count <= max_retries:
            try:
                # Make the request
                response = requests.get(url, headers=headers, params=params)
                
                # If successful or non-throttling error, return
                if response.status_code < 429 or response.status_code >= 500:
                    return response
                    
                # Handle throttling (429)
                if response.status_code == 429:
                    # Get retry-after header if available
                    retry_after = response.headers.get('Retry-After')
                    if retry_after:
                        wait_time = int(retry_after)
                    else:
                        # Calculate exponential backoff
                        wait_time = base_wait_time * (2 ** retry_count)
                        wait_time = min(wait_time, 120)  # Cap at 2 minutes
                    
                    print(f"Request throttled. Waiting {wait_time} seconds before retry. (Attempt {retry_count + 1}/{max_retries})")
                    time.sleep(wait_time)
                    retry_count += 1
                    continue
                    
            except Exception as e:
                if retry_count < max_retries:
                    wait_time = base_wait_time * (2 ** retry_count)
                    wait_time = min(wait_time, 120)  # Cap at 2 minutes
                    print(f"Request error: {e}. Retrying in {wait_time} seconds. (Attempt {retry_count + 1}/{max_retries})")
                    time.sleep(wait_time)
                    retry_count += 1
                else:
                    raise Exception(f"Max retries exceeded during request: {e}")
        
        # If we get here, we've exceeded max retries
        raise Exception(f"Request failed after {max_retries} retries: {url}")
    
    def process_signin_data(self, sign_ins):
        """Process raw sign-in data to extract relevant information and format it for CSV
        
        Args:
            sign_ins: List of sign-in records from Microsoft Graph API
            
        Returns:
            List of processed sign-in records
        """
        processed_records = []
        est_timezone = pytz.timezone('US/Eastern')
        
        # Debug: print keys in the first record if available
        if sign_ins and len(sign_ins) > 0:
            print(f"Sample sign-in record keys: {list(sign_ins[0].keys())}")
            if 'location' in sign_ins[0]:
                print(f"Sample location keys: {list(sign_ins[0]['location'].keys())}")
                if 'geoCoordinates' in sign_ins[0]['location']:
                    print(f"  geoCoordinates: {sign_ins[0]['location']['geoCoordinates']}")
            if 'deviceDetail' in sign_ins[0]:
                print(f"Sample deviceDetail keys: {list(sign_ins[0]['deviceDetail'].keys())}")
            if 'clientAppUsed' in sign_ins[0]:
                print(f"Client app used: {sign_ins[0]['clientAppUsed']}")
            if 'userAgent' in sign_ins[0]:
                print(f"Sample userAgent: {sign_ins[0]['userAgent']}")
        
        for record in sign_ins:
            try:
                # Extract basic info
                user_email = record.get("userPrincipalName", "").lower()
                request_id = record.get("id", "")
                app_name = record.get("appDisplayName", "")
                
                # Extract device information
                device_id = ""
                device_name = ""
                browser_name = ""
                os_name = ""
                client_app = record.get("clientAppUsed", "")
                user_agent = record.get("userAgent", "")
                device_fingerprint = ""
                
                if "deviceDetail" in record:
                    device_detail = record.get("deviceDetail", {})
                    device_id = device_detail.get("deviceId", "")
                    device_name = device_detail.get("displayName", "")
                    browser = device_detail.get("browser", "")
                    os = device_detail.get("operatingSystem", "")
                    device_trust_type = device_detail.get("trustType", "")
                    
                    # Set browser and OS names
                    if device_name:
                        os_name = os
                        browser_name = browser
                    else:
                        device_name = os  # Use OS as device name if no display name
                        os_name = os
                        browser_name = browser
                    
                    # Generate a fingerprint from available data for ALL devices
                    fingerprint_parts = []
                    
                    # If device has a deviceId, include it for stability
                    if device_id:
                        fingerprint_parts.append(device_id)
                    
                    # Include user email for per-user uniqueness
                    if user_email:
                        fingerprint_parts.append(user_email)
                        
                    # Add device name if available
                    if device_name:
                        fingerprint_parts.append(device_name)
                        
                    # Add OS and browser info
                    if os:
                        fingerprint_parts.append(os)
                    if browser:
                        fingerprint_parts.append(browser)
                        
                    # Add client app info
                    if client_app:
                        fingerprint_parts.append(client_app)
                        
                    # Extract useful info from user agent
                    if user_agent:
                        # Extract key parts of user agent to keep fingerprint stable
                        ua_parts = []
                        if "iPhone" in user_agent or "iPad" in user_agent:
                            ua_parts.append("Apple")
                            if "OS " in user_agent:
                                # Extract iOS version
                                ios_version = re.search(r"OS (\d+_\d+)", user_agent)
                                if ios_version:
                                    ua_parts.append(f"iOS{ios_version.group(1).replace('_', '.')}")
                        elif "Android" in user_agent:
                            ua_parts.append("Android")
                            android_version = re.search(r"Android (\d+\.?\d*)", user_agent)
                            if android_version:
                                ua_parts.append(android_version.group(0))
                        elif "Windows" in user_agent:
                            windows_version = re.search(r"Windows NT (\d+\.?\d*)", user_agent)
                            if windows_version:
                                ua_parts.append(f"Windows{windows_version.group(1)}")
                        elif "Mac OS X" in user_agent:
                            mac_version = re.search(r"Mac OS X (\d+[_\.]\d+)", user_agent)
                            if mac_version:
                                ua_parts.append(f"MacOS{mac_version.group(1).replace('_', '.')}")
                        
                        if ua_parts:
                            fingerprint_parts.extend(ua_parts)
                            
                    # Create a stable fingerprint if we have enough data
                    if len(fingerprint_parts) >= 2:
                        # Use a hash of the combined fingerprint parts to create a stable ID
                        fingerprint_string = "_".join(fingerprint_parts)
                        import hashlib
                        device_fingerprint = hashlib.md5(fingerprint_string.encode()).hexdigest()
                
                # Process timestamp - convert to EST
                timestamp_utc = datetime.datetime.fromisoformat(record.get("createdDateTime", "").replace('Z', '+00:00'))
                timestamp_est = timestamp_utc.astimezone(est_timezone)
                formatted_time = timestamp_est.strftime("%Y-%m-%d %H:%M:%S")
                
                # Extract hour and day of week for time-based analysis
                hour = timestamp_est.hour
                day_of_week = timestamp_est.weekday()  # 0=Monday, 6=Sunday
                
                # Process IP address - check standard location
                ip_address = ""
                # First check if ipAddress is directly in the main record
                if "ipAddress" in record:
                    ip_address = record.get("ipAddress", "")
                
                # Second, check in the location object if present
                if not ip_address and "location" in record:
                    location_info = record.get("location", {})
                    ip_address = location_info.get("ipAddress", "")
                
                # Third, check in the client info if present
                if not ip_address and "clientInfo" in record:
                    client_info = record.get("clientInfo", {})
                    ip_address = client_info.get("ipAddress", "")
                
                # Last check in IP address information object
                if not ip_address and "ipAddressInfo" in record:
                    ip_address_info = record.get("ipAddressInfo", {})
                    ip_address = ip_address_info.get("ipAddress", "")
                    
                # Debug IP address extraction
                if not ip_address:
                    print(f"No IP address found for {user_email}")
                    print(f"Record keys: {list(record.keys())}")
                
                # Process location info
                location_info = record.get("location", {})
                city = location_info.get("city", "")
                state = location_info.get("state", "")
                country = location_info.get("countryOrRegion", "")
                
                # Extract geo coordinates if available
                latitude = None
                longitude = None
                if "geoCoordinates" in location_info:
                    geo_coords = location_info.get("geoCoordinates", {})
                    latitude = geo_coords.get("latitude")
                    longitude = geo_coords.get("longitude")
                
                # Format location string
                location = f"{city}, {state}, {country}".replace(", ,", ",").strip(", ")
                
                # Create processed record
                processed_record = {
                    "request_id": request_id,
                    "timestamp": formatted_time,
                    "timestamp_obj": timestamp_est,  # Keep datetime object for sorting
                    "user_email": user_email,
                    "application": app_name,
                    "ip_address": ip_address,
                    "location": location,
                    "city": city,
                    "state": state,
                    "country": country,
                    "latitude": latitude,
                    "longitude": longitude,
                    "device_id": device_id,
                    "device_name": device_name,
                    "device_fingerprint": device_fingerprint,
                    "browser": browser_name,
                    "os": os_name,
                    "client_app": client_app,
                    "hour": hour,
                    "day_of_week": day_of_week
                }
                
                processed_records.append(processed_record)
                
            except Exception as e:
                print(f"Error processing sign-in record: {e}")
                continue
        
        return processed_records
    
    def update_login_history(self, processed_records, mode="append"):
        """
        Update the login history CSV file with new records
        
        Args:
            processed_records: List of processed sign-in records
            mode: "append" to add to existing file, "overwrite" to create new file
        """
        # Ensure Data directory exists
        os.makedirs(os.path.join(self.script_dir, "Data"), exist_ok=True)
        
        # Sort records by user and timestamp
        sorted_records = sorted(
            processed_records, 
            key=lambda x: (x["user_email"], x["timestamp_obj"])
        )
        
        # Determine if file exists
        file_exists = os.path.exists(self.login_history_path)
        
        # Load existing records if appending
        existing_records = []
        if mode == "append" and file_exists:
            try:
                with open(self.login_history_path, 'r', newline='', encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)
                    for row in reader:
                        existing_records.append(row)
            except Exception as e:
                print(f"Error reading existing login history: {e}")
        
        # Open file for writing
        write_mode = 'a' if mode == "append" and file_exists else 'w'
        with open(self.login_history_path, write_mode, newline='', encoding='utf-8') as csvfile:
            fieldnames = ["request_id", "timestamp", "user_email", "application", 
                         "ip_address", "location", "city", "state", "country", 
                         "latitude", "longitude", "device_id", "device_name",
                         "device_fingerprint", "browser", "os", "client_app",
                         "hour", "day_of_week"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            # Write header if new file or overwriting
            if write_mode == 'w':
                writer.writeheader()
            
            # Write records, removing the timestamp_obj that was only used for sorting
            for record in sorted_records:
                record_copy = record.copy()
                if "timestamp_obj" in record_copy:
                    del record_copy["timestamp_obj"]
                writer.writerow(record_copy)
    
    def get_date_range_for_training(self):
        """Calculate start and end dates for training mode"""
        end_time = datetime.datetime.now(pytz.utc)
        start_time = end_time - datetime.timedelta(days=self.config["training_days"])
        
        # Format as ISO strings
        start_time_iso = start_time.isoformat().replace('+00:00', 'Z')
        end_time_iso = end_time.isoformat().replace('+00:00', 'Z')
        
        return start_time_iso, end_time_iso
    
    def get_last_fetch_time(self):
        """Get the timestamp of the last successful fetch"""
        if not os.path.exists(self.last_fetch_path):
            # Default to 24 hours ago if no file exists
            last_time = datetime.datetime.now(pytz.utc) - datetime.timedelta(hours=24)
            return last_time.isoformat().replace('+00:00', 'Z')
            
        try:
            with open(self.last_fetch_path, 'r') as file:
                data = json.load(file)
                return data.get("last_fetch_time")
        except Exception as e:
            print(f"Error reading last fetch time: {e}")
            # Default to 24 hours ago if error occurs
            last_time = datetime.datetime.now(pytz.utc) - datetime.timedelta(hours=24)
            return last_time.isoformat().replace('+00:00', 'Z')
    
    def update_last_fetch_time(self, fetch_time=None):
        """Update the timestamp of the last successful fetch"""
        if fetch_time is None:
            fetch_time = datetime.datetime.now(pytz.utc).isoformat().replace('+00:00', 'Z')
            
        data = {"last_fetch_time": fetch_time}
        
        try:
            with open(self.last_fetch_path, 'w') as file:
                json.dump(data, file)
        except Exception as e:
            print(f"Error updating last fetch time: {e}")
            
    def run(self):
        """Main method to run the monitoring process"""
        print(f"Starting Azure Sign-In Monitor - Training Mode: {self.config['training_mode']}")
        
        if self.config['training_mode']:
            self._run_training_mode()
        else:
            self._run_standard_mode()
    
    def _run_training_mode(self):
        """Run in training mode - collecting historical data"""
        print(f"Running in training mode for the past {self.config['training_days']} days")
        
        # Check if we should use existing login history data
        if self.config["use_existing_login_history_csv"]:
            print("Using existing login_history.csv data for training (skipping data fetch)")
            
            # Check if login history file exists
            if not os.path.exists(self.login_history_path):
                print(f"Error: login_history.csv not found at {self.login_history_path}")
                print("Cannot use existing data. Please set USE_EXISTING_LOGIN_HISTORY_CSV=False to fetch new data.")
                return
            
            print("Building whitelists from existing login history data...")
            
            # Load existing data for suspicious login analysis
            processed_records = []
            try:
                with open(self.login_history_path, 'r', newline='', encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)
                    for row in reader:
                        # Convert CSV row back to processed record format
                        processed_record = {
                            "request_id": row.get("request_id", ""),
                            "timestamp": row.get("timestamp", ""),
                            "user_email": row.get("user_email", ""),
                            "application": row.get("application", ""),
                            "ip_address": row.get("ip_address", ""),
                            "location": row.get("location", ""),
                            "city": row.get("city", ""),
                            "state": row.get("state", ""),
                            "country": row.get("country", ""),
                            "latitude": float(row.get("latitude")) if row.get("latitude") else None,
                            "longitude": float(row.get("longitude")) if row.get("longitude") else None,
                            "device_id": row.get("device_id", ""),
                            "device_name": row.get("device_name", ""),
                            "device_fingerprint": row.get("device_fingerprint", ""),
                            "browser": row.get("browser", ""),
                            "os": row.get("os", ""),
                            "client_app": row.get("client_app", ""),
                            "hour": int(row.get("hour")) if row.get("hour") else None,
                            "day_of_week": int(row.get("day_of_week")) if row.get("day_of_week") else None
                        }
                        processed_records.append(processed_record)
                        
                print(f"Loaded {len(processed_records)} existing login records from login_history.csv")
                
            except Exception as e:
                print(f"Error loading existing login history: {e}")
                return
                
        else:
            print("Fetching new training data from Microsoft Graph API")
            
            # 1. Get date range for training
            start_time, end_time = self.get_date_range_for_training()
            print(f"Fetching sign-ins from {start_time} to {end_time}")
            
            # 2. Fetch historical sign-ins
            sign_ins = self.fetch_signin_logs(start_time, end_time)
            
            # 3. Process sign-in data
            processed_records = self.process_signin_data(sign_ins)
            
            # 4. Create/update login_history.csv
            self.update_login_history(processed_records, mode="overwrite")
            
            # Update last fetch time
            self.update_last_fetch_time(end_time)
            
            print("Training data collection completed. Login history has been created.")
        
        # 5. Build whitelist from login history
        self.build_whitelist()
        
        # 6. Analyze device fingerprints and create whitelist
        if self.config["exclude_whitelisted_fingerprints"]:
            self.analyze_device_fingerprints()
        else:
            print("Device fingerprint whitelisting is disabled. Skipping fingerprint analysis.")
        
        # 7. Analyze for suspicious sign-ins
        suspicious_logins = self.analyze_suspicious_logins(processed_records)
        
        # 8. Generate and send report if suspicious logins found
        if suspicious_logins:
            self.generate_suspicious_report(suspicious_logins, self.training_report_path)
            
            # Check if training emails are enabled
            if self.config.get("send_training_emails", True):
                print("Sending training suspicious login report via email...")
                
                # If Teams notification is also enabled, handle through send_report
                if self.config.get("teams_notification", False):
                    self.send_report(self.training_report_path, include_teams_notification=True)
                else:
                    self.send_report(self.training_report_path, include_teams_notification=False)
            else:
                print("Training email notifications are disabled. Report generated but not sent.")
                
                # If emails are disabled but Teams notifications are enabled,
                # we need to explicitly send the Teams notification
                if self.config.get("teams_notification", False):
                    print("Sending Teams notification for training data...")
                    self.send_teams_notification(self.training_report_path)
        else:
            print("No suspicious logins found during training period.")
        
        print("Training mode completed. Switching to standard monitoring mode.")
        
        # Switch to standard mode
        self.config["training_mode"] = False
        self._run_standard_mode()
    
    def _run_standard_mode(self):
        """Run in standard monitoring mode"""
        print("Running in standard monitoring mode")
        
        # Load whitelist if needed
        if not self.whitelists:
            self.load_whitelist()
            
        if not self.whitelists:
            print("Error: No whitelist available. Run in training mode first.")
            return
        
        # Load device fingerprint whitelist if enabled
        if self.config["exclude_whitelisted_fingerprints"] and not self.fingerprint_whitelist:
            self.load_fingerprint_whitelist()
        
        while not self.shutdown_requested:
            try:
                # Check for shutdown request
                self._check_for_shutdown()
                
                # 1. Get last fetch time
                last_fetch_time = self.get_last_fetch_time()
                current_time = datetime.datetime.now(pytz.utc).isoformat().replace('+00:00', 'Z')
                
                # Add a buffer time to account for delays in Azure's logging system
                # Check if last_fetch_time is a string before parsing
                if isinstance(last_fetch_time, str):
                    last_fetch_dt = datetime.datetime.fromisoformat(last_fetch_time.replace('Z', '+00:00'))
                    # Add a 15-minute buffer to look back further
                    buffer_minutes = 15
                    last_fetch_dt = last_fetch_dt - datetime.timedelta(minutes=buffer_minutes)
                    last_fetch_time = last_fetch_dt.isoformat().replace('+00:00', 'Z')
                    print(f"Using buffered fetch window (added {buffer_minutes} minute lookback)")
                
                print(f"Fetching sign-ins from {last_fetch_time} to {current_time}")
                
                # 2. Fetch new sign-ins
                sign_ins = self.fetch_signin_logs(last_fetch_time, current_time)
                
                # Check for shutdown after long operations
                self._check_for_shutdown()
                
                if sign_ins:
                    # 3. Process sign-in data
                    processed_records = self.process_signin_data(sign_ins)
                    
                    # 4. Update login_history.csv
                    if processed_records:
                        self.update_login_history(processed_records, mode="append")
                        print(f"Added {len(processed_records)} new sign-ins to login history")
                        
                        # Check for shutdown after long operations
                        self._check_for_shutdown()
                        
                        # Update whitelists retroactively based on new sign-ins
                        location_updates, fingerprint_updates = self.update_whitelists_for_users(processed_records)
                    
                        # 5. Analyze for suspicious sign-ins
                        suspicious_logins = self.analyze_suspicious_logins(processed_records)
                        
                        # 6. Generate and send report if suspicious logins found
                        if suspicious_logins:
                            # Create timestamped filename for this polling period
                            # Format the start and end times for the report filename
                            if isinstance(last_fetch_time, str):
                                start_dt = datetime.datetime.fromisoformat(last_fetch_time.replace('Z', '+00:00'))
                                start_time_local = start_dt.astimezone(datetime.datetime.now().astimezone().tzinfo)
                                start_str = start_time_local.strftime("%Y%m%d_%H%M%S")
                            else:
                                start_str = "unknown_start"
                                
                            if isinstance(current_time, str):
                                end_dt = datetime.datetime.fromisoformat(current_time.replace('Z', '+00:00'))
                                end_time_local = end_dt.astimezone(datetime.datetime.now().astimezone().tzinfo)
                                end_str = end_time_local.strftime("%Y%m%d_%H%M%S")
                            else:
                                end_str = "unknown_end"
                            
                            # Create a readable timespan for the summary text
                            if isinstance(start_time_local, datetime.datetime) and isinstance(end_time_local, datetime.datetime):
                                start_readable = start_time_local.strftime("%m/%d/%Y %I:%M%p %Z")
                                end_readable = end_time_local.strftime("%m/%d/%Y %I:%M%p %Z")
                                timespan_text = f"{start_readable} to {end_readable}"
                            else:
                                timespan_text = "Unknown timespan"
                            
                            # Set the report path for this polling period
                            self.suspicious_report_path = os.path.join(
                                self.script_dir, "Polling Reports", 
                                f"suspicious_signin_report_{start_str}_to_{end_str}.csv"
                            )
                            
                            # Generate the report
                            self.generate_suspicious_report(suspicious_logins, self.suspicious_report_path)
                            
                            # Check for shutdown before sending email
                            if not self.shutdown_requested:
                                # Check if monitoring emails are enabled
                                if self.config.get("send_monitoring_emails", True):
                                    print("Sending suspicious login report via email...")
                                    # Use send_report to handle both email and Teams notifications if needed
                                    if self.config.get("teams_notification", False):
                                        self.send_report(self.suspicious_report_path, include_teams_notification=True)
                                        print(f"Detected {len(suspicious_logins)} suspicious logins. Report sent.")
                                    else:
                                        self.send_report(self.suspicious_report_path, include_teams_notification=False)
                                        print(f"Detected {len(suspicious_logins)} suspicious logins. Report sent.")
                                else:
                                    print(f"Detected {len(suspicious_logins)} suspicious logins. Email notifications disabled.")
                                    
                                    # If emails are disabled but Teams notifications are enabled,
                                    # send the Teams notification directly
                                    if self.config.get("teams_notification", False) and not self.shutdown_requested:
                                        summary_text = f"Detected {len(suspicious_logins)} suspicious sign-ins from {timespan_text}"
                                        self.send_teams_notification(self.suspicious_report_path, summary_text, suspicious_logins)
                        else:
                            if location_updates > 0 or fingerprint_updates > 0:
                                print(f"No suspicious logins found in this batch.")
                            else:
                                print("No suspicious logins found in this batch.")
                
                # Log any alerts that were excluded due to device exceptions
                self.log_excluded_alerts()
                
                # 7. Update last fetch time (without buffer)
                # Only store the actual current_time so we don't lose the most recent data
                self.update_last_fetch_time(current_time)
                
                # 8. Wait for polling period with interruption checks
                if not self.shutdown_requested:
                    print(f"Waiting for {self.config['polling_period_minutes']} minutes until next check...")
                    
                    # Break the sleep into smaller intervals to allow for quicker shutdown
                    polling_seconds = self.config['polling_period_minutes'] * 60
                    sleep_interval = min(10, polling_seconds)  # Check every 10 seconds or less
                    
                    for _ in range(0, polling_seconds, sleep_interval):
                        if self.shutdown_requested:
                            break
                        time.sleep(sleep_interval)
                
            except KeyboardInterrupt:
                print("\nKeyboard interrupt received. Exiting gracefully...")
                self.shutdown_requested = True
                break
            except Exception as e:
                print(f"Error in standard mode: {e}")
                
                if not self.shutdown_requested:
                    print(f"Retrying in {self.config['polling_period_minutes']} minutes...")
                    
                    # Break the sleep into smaller intervals to allow for quicker shutdown
                    polling_seconds = self.config['polling_period_minutes'] * 60
                    sleep_interval = min(10, polling_seconds)  # Check every 10 seconds or less
                    
                    for _ in range(0, polling_seconds, sleep_interval):
                        if self.shutdown_requested:
                            break
                        time.sleep(sleep_interval)
        
        print("Monitoring stopped. Exiting...")
    
    def build_whitelist(self):
        """Build whitelists of safe locations and times for each user
        
        This analyzes login_history.csv to identify:
        1. Common login locations (city, state, country)
        2. Typical login hours using 5th and 95th percentiles
        
        Returns:
            Dictionary of whitelists by user email
        """
        print("Building user whitelists from login history...")
        
        if not os.path.exists(self.login_history_path):
            print(f"Error: Login history file not found at {self.login_history_path}")
            return {}
        
        # Load login history
        user_logins = {}
        try:
            with open(self.login_history_path, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    user_email = row.get("user_email", "").lower()
                    
                    if not user_email:
                        continue
                        
                    if user_email not in user_logins:
                        user_logins[user_email] = []
                        
                    # Parse timestamp for hour analysis
                    try:
                        timestamp = row.get("timestamp", "")
                        dt = datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
                        # Convert to decimal hours (e.g., 9:30 -> 9.5)
                        hour_decimal = dt.hour + (dt.minute / 60.0)
                    except Exception as e:
                        print(f"Error parsing timestamp for {user_email}: {e}")
                        hour_decimal = None
                    
                    login_data = {
                        "city": row.get("city", ""),
                        "state": row.get("state", ""),
                        "country": row.get("country", ""),
                        "location": row.get("location", ""),
                        "ip_address": row.get("ip_address", ""),
                        "hour_decimal": hour_decimal
                    }
                    
                    user_logins[user_email].append(login_data)
        except Exception as e:
            print(f"Error reading login history: {e}")
            return {}
        
        # Process each user's logins to build whitelist
        whitelists = {}
        
        for user_email, logins in user_logins.items():
            print(f"Building whitelist for {user_email} ({len(logins)} logins)")
            
            # Skip if user has too few logins
            if len(logins) < 3:
                print(f"  Not enough login data for {user_email} (minimum 3 required)")
                continue
                
            # Count locations
            location_count = {}
            for login in logins:
                location_key = f"{login['city']}, {login['state']}, {login['country']}".replace(", ,", ",").strip(", ")
                
                if not location_key or location_key == ",,":
                    continue
                    
                if location_key not in location_count:
                    location_count[location_key] = 0
                    
                location_count[location_key] += 1
            
            # Collect hours for percentile calculation
            valid_hours = []
            for login in logins:
                if login["hour_decimal"] is not None:
                    valid_hours.append(login["hour_decimal"])
            
            # Calculate location frequency threshold
            total_logins = len(logins)
            location_threshold = max(2, int(total_logins * self.config["location_frequency_threshold"]))
            
            # Find safe locations (those appearing more than the threshold)
            safe_locations = []
            for location, count in location_count.items():
                if count >= location_threshold:
                    safe_locations.append({
                        "location": location,
                        "count": count,
                        "percentage": (count / total_logins) * 100
                    })
                    print(f"  Safe location: {location} ({count}/{total_logins} logins, {(count/total_logins)*100:.1f}%)")
            
            # Calculate 5th and 95th percentiles of login times
            work_hours = [0, 24]  # Default to full day if not enough data
            if valid_hours and len(valid_hours) >= 5:  # Need enough data for percentiles
                valid_hours.sort()
                # Calculate 5th percentile for start time
                start_idx = max(0, int(0.05 * len(valid_hours)) - 1)
                # Calculate 95th percentile for end time
                end_idx = min(len(valid_hours) - 1, int(0.95 * len(valid_hours)))
                
                start_time = valid_hours[start_idx]
                end_time = valid_hours[end_idx]
                
                # Convert decimal hours to integer hours
                start_hour = int(start_time)
                end_hour = int(end_time + 0.99)  # Round up to include the full hour
                
                # Make sure we have valid hours
                start_hour = max(0, min(23, start_hour))
                end_hour = max(0, min(23, end_hour))
                
                work_hours = [start_hour, end_hour]
                
                print(f"  Work hours (5th-95th percentile): {start_hour:02d}:00 - {end_hour:02d}:59")
            
            # Create whitelist for this user
            whitelists[user_email] = {
                "locations": safe_locations,
                "work_hours": work_hours,
                "international_user": False  # No longer used - kept for backward compatibility
            }
        
        # Save whitelist to file
        self.save_whitelist(whitelists)
        
        # Store in instance variable
        self.whitelists = whitelists
        
        return whitelists
    
    def save_whitelist(self, whitelists):
        """Save whitelist to JSON file"""
        try:
            with open(self.whitelist_path, 'w') as file:
                json.dump(whitelists, file, indent=2)
            print(f"Whitelist saved to {self.whitelist_path}")
        except Exception as e:
            print(f"Error saving whitelist: {e}")
    
    def load_whitelist(self):
        """Load whitelist from JSON file"""
        if not os.path.exists(self.whitelist_path):
            print(f"Whitelist file not found at {self.whitelist_path}")
            return {}
            
        try:
            with open(self.whitelist_path, 'r') as file:
                whitelists = json.load(file)
            print(f"Whitelist loaded from {self.whitelist_path}")
            self.whitelists = whitelists
            return whitelists
        except Exception as e:
            print(f"Error loading whitelist: {e}")
            return {}
    
    def analyze_suspicious_logins(self, logins):
        """Analyze sign-ins for suspicious activity
        
        Detects:
        1. Logins from locations not in user's whitelist (if check_location=True)
        2. Logins outside normal working hours (if check_unusual_hours=True)
        3. Impossible travel between logins (if check_impossible_travel=True)
        
        Args:
            logins: List of processed login records
            
        Returns:
            List of suspicious login records with reasons
        """
        suspicious_logins = []
        self.excluded_alerts = []  # Reset excluded alerts for this batch
        
        # Make sure we have whitelist data
        if not self.whitelists:
            print("No whitelist data available for analysis")
            return suspicious_logins
        
        print(f"Analyzing {len(logins)} logins for suspicious activity...")
        
        try:
            # Group logins by user for impossible travel detection
            user_logins = {}
            for login in logins:
                if not isinstance(login, dict):
                    print(f"Warning: Found non-dictionary login entry, skipping: {login}")
                    continue
                    
                user_email = login.get("user_email", "").lower()
                if not user_email:
                    continue
                    
                if user_email not in user_logins:
                    user_logins[user_email] = []
                    
                user_logins[user_email].append(login)
                
            # Process impossible travel detection first if enabled
            impossible_travel_results = {}
            if self.config["check_impossible_travel"]:
                print("Checking for impossible travel patterns...")
                for user_email, user_login_list in user_logins.items():
                    try:
                        # Skip international/shared accounts for impossible travel check
                        if user_email in self.config["international_users"]:
                            continue
                            
                        # Get historical logins for this user to ensure we check against all adjacent logins
                        historical_logins = self.get_user_login_history(user_email)
                        
                        # Merge with current logins (they might overlap)
                        all_user_logins = historical_logins + user_login_list
                        
                        # Remove duplicates based on request_id
                        seen_request_ids = set()
                        unique_logins = []
                        for login in all_user_logins:
                            request_id = login.get('request_id')
                            if request_id and request_id not in seen_request_ids:
                                seen_request_ids.add(request_id)
                                unique_logins.append(login)
                        
                        # Detect impossible travel
                        user_impossible_travel = self.detect_impossible_travel(unique_logins)
                        impossible_travel_results.update(user_impossible_travel)
                        
                        if user_impossible_travel:
                            print(f"Found {len(user_impossible_travel)} impossible travel patterns for {user_email}")
                    except Exception as e:
                        print(f"Error analyzing impossible travel for user {user_email}: {e}")
                        # Continue with next user
            
            # Check each login for suspicious activity
            for login in logins:
                try:
                    suspicious_reasons = []
                    
                    if not isinstance(login, dict):
                        continue
                    
                    # Extract basic user info
                    user_email = login.get("user_email", "").lower()
                    request_id = login.get("request_id", "")
                    
                    # Skip already reported logins
                    if request_id in self.reported_suspicious_ids:
                        continue
                        
                    # Skip if no user email (shouldn't happen, but just in case)
                    if not user_email:
                        continue
                    
                    # Check if this login should be excluded based on device_id
                    device_id = login.get("device_id", "")
                    device_fingerprint = login.get("device_fingerprint", "")
                    ip_address = login.get("ip_address", "")
                    
                    # Track if this login should be excluded from alerts, but still used for impossible travel
                    excluded_from_alerts = False
                    exclusion_reason = ""
                    
                    # Check for device ID exclusion
                    if self.config["exclude_enrolled_devices"] and device_id:
                        excluded_from_alerts = True
                        exclusion_reason = "Enrolled device (has device_id)"
                    
                    # Check for whitelisted fingerprint exclusion
                    elif (self.config["exclude_whitelisted_fingerprints"] and 
                          device_fingerprint and 
                          device_fingerprint in self.fingerprint_whitelist):
                        excluded_from_alerts = True
                        exclusion_reason = "Whitelisted device fingerprint"
                    
                    # Check for whitelisted IP exclusion
                    elif (self.config["exclude_whitelisted_ips"] and 
                          ip_address and 
                          ip_address in self.config["whitelisted_ips"]):
                        excluded_from_alerts = True
                        exclusion_reason = "Whitelisted IP address"
                    
                    # Get user whitelist
                    user_whitelist = self.whitelists.get(user_email, {})
                    
                    if not isinstance(user_whitelist, dict):
                        print(f"Warning: Invalid whitelist for user {user_email}, expected dict, got {type(user_whitelist)}")
                        continue
                    
                    safe_locations = user_whitelist.get("locations", {})
                    if not isinstance(safe_locations, dict):
                        # Try to handle if it's a list of dictionaries (old format)
                        if isinstance(safe_locations, list):
                            temp_locations = {}
                            for loc in safe_locations:
                                if isinstance(loc, dict) and "location" in loc:
                                    temp_locations[loc["location"]] = loc.get("frequency", 0)
                            safe_locations = temp_locations
                        else:
                            # If not convertible, use empty dict
                            safe_locations = {}
                    
                    work_hours = user_whitelist.get("work_hours", {})
                    
                    # Check if this is a shared account (international user)
                    is_shared_account = user_email in self.config["international_users"]
                    
                    # Check 1: Login from unusual location (if enabled and not a shared account)
                    if not excluded_from_alerts and self.config["check_location"] and not is_shared_account:
                        location = login.get("location", "")
                        app_name = login.get("application", "")
                        
                        # Skip exempt applications for unusual location check
                        if app_name and app_name in self.config["unusual_location_exempt_apps"]:
                            pass  # Skip location check but continue with other checks
                        # Check against whitelist
                        elif location and location not in safe_locations:
                            # Calculate frequency threshold for this location
                            location_freq = safe_locations.get(location, 0)
                            if location_freq < self.config["location_frequency_threshold"]:
                                reason = f"Login from unusual location: {location}"
                                suspicious_reasons.append(reason)
                    
                    # Check 2: Login outside normal work hours (if enabled)
                    if not excluded_from_alerts and self.config["check_unusual_hours"]:
                        login_hour = login.get("hour")
                        login_day = login.get("day_of_week")
                        
                        if login_hour is not None and login_day is not None:
                            # Handle both old and new formats for work_hours
                            if isinstance(work_hours, list):
                                # Old format: [start_hour, end_hour]
                                normal_start = work_hours[0] if len(work_hours) > 0 else 8
                                normal_end = work_hours[1] if len(work_hours) > 1 else 18
                            else:
                                # New format: dictionary by day of week
                                day_key = str(login_day)
                                if day_key in work_hours and isinstance(work_hours[day_key], dict):
                                    day_hours = work_hours[day_key]
                                    normal_start = day_hours.get("start", 8)
                                    normal_end = day_hours.get("end", 18)
                                else:
                                    # Default to standard business hours if no history
                                    normal_start = 8
                                    normal_end = 18
                            
                            # Add buffer for occasional early/late work
                            buffer_hours = self.config["time_outlier_threshold_hours"]
                            extended_start = max(0, normal_start - buffer_hours)
                            extended_end = min(24, normal_end + buffer_hours)
                            
                            # Check if login is outside extended hours
                            if login_hour < extended_start or login_hour > extended_end:
                                reason = f"Login outside normal hours: {login_hour}:00 (normal: {normal_start}:00-{normal_end}:00)"
                                suspicious_reasons.append(reason)
                    
                    # Check 3: Impossible travel (only if enabled and not a shared account)
                    # Note: Impossible travel is checked regardless of device exclusions
                    if self.config["check_impossible_travel"] and not is_shared_account:
                        if request_id in impossible_travel_results:
                            travel_details = impossible_travel_results[request_id]
                            
                            # Format the travel time for readability
                            time_hours = int(travel_details['time_diff_hours'])
                            time_minutes = int((travel_details['time_diff_hours'] - time_hours) * 60)
                            time_str = f"{time_hours}h {time_minutes}m"
                            
                            # Add reason
                            reason = (f"Impossible travel from {travel_details['from_location']} in {time_str} "
                                     f"({travel_details['distance_miles']} miles, {travel_details['travel_speed_mph']} mph)")
                            suspicious_reasons.append(reason)
                        
                    # If any suspicious reasons found, add to list if not excluded
                    if suspicious_reasons:
                        if excluded_from_alerts:
                            # Log the excluded alert
                            excluded_alert = login.copy()
                            excluded_alert["reasons"] = ",".join(suspicious_reasons)
                            excluded_alert["exclusion_reason"] = exclusion_reason
                            self.excluded_alerts.append(excluded_alert)
                            print(f"Excluded alert for {user_email}: {excluded_alert['reasons']} - {exclusion_reason}")
                        else:
                            suspicious_login = login.copy()
                            suspicious_login["reasons"] = ",".join(suspicious_reasons)
                            suspicious_logins.append(suspicious_login)
                            
                            # Add to reported IDs to prevent duplicates in future
                            self.reported_suspicious_ids.add(request_id)
                
                except Exception as e:
                    print(f"Error analyzing login {login.get('request_id', 'unknown')}: {e}")
                    # Continue with next login
            
            # Log excluded alerts if any
            if self.excluded_alerts:
                self.log_excluded_alerts()
                
            print(f"Found {len(suspicious_logins)} suspicious logins")
            print(f"Excluded {len(self.excluded_alerts)} alerts due to device exclusions")
            return suspicious_logins
            
        except Exception as e:
            print(f"Unhandled exception in analyze_suspicious_logins: {e}")
            print(traceback.format_exc())
            # Return partial results if available, otherwise empty list
            return suspicious_logins
    
    def generate_suspicious_report(self, suspicious_logins, report_path):
        """Generate CSV report of suspicious logins
        
        Args:
            suspicious_logins: List of suspicious login records with reasons
            report_path: Path to save the report
        """
        print(f"Generating suspicious login report at {report_path}")
        
        with open(report_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ["request_id", "timestamp", "user_email", "application", 
                         "ip_address", "location", "device_id", "device_name", 
                         "device_fingerprint", "browser", "os", "client_app", "reasons"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Write records
            for login in suspicious_logins:
                # Create a copy with only the fields we want
                record = {
                    "request_id": login.get("request_id", ""),
                    "timestamp": login.get("timestamp", ""),
                    "user_email": login.get("user_email", ""),
                    "application": login.get("application", ""),
                    "ip_address": login.get("ip_address", ""),
                    "location": login.get("location", ""),
                    "device_id": login.get("device_id", ""),
                    "device_name": login.get("device_name", ""),
                    "device_fingerprint": login.get("device_fingerprint", ""),
                    "browser": login.get("browser", ""),
                    "os": login.get("os", ""),
                    "client_app": login.get("client_app", ""),
                    "reasons": login.get("reasons", "")
                }
                
                writer.writerow(record)
        
        print(f"Report generated with {len(suspicious_logins)} suspicious logins")
    
    def send_report(self, report_path, include_teams_notification=True):
        """Send the suspicious sign-in report via email and Teams (if enabled)
        
        Args:
            report_path: Path to the report file to send
            include_teams_notification: Whether to also send Teams notification
            
        Returns:
            Boolean indicating if at least one notification method succeeded
        """
        if not os.path.exists(report_path):
            print(f"Error: Report file not found at {report_path}")
            return False
            
        email_success = False
        teams_success = False
        
        # Count suspicious logins and load them for Teams notification
        suspicious_logins = []
        try:
            with open(report_path, 'r', newline='', encoding='utf-8') as file:
                reader = csv.DictReader(file)
                suspicious_logins = list(reader)
                suspicious_count = len(suspicious_logins)
        except Exception as e:
            print(f"Error reading suspicious logins: {e}")
            suspicious_count = 0
            
        # Generate summary text
        summary_text = f"Detected {suspicious_count} suspicious Azure sign-ins - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
        
        # Send email notification
        print(f"Sending report email to {self.config['recipient_email']}")
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.config['sender_email']
            msg['To'] = self.config['recipient_email']
            msg['Subject'] = f"Suspicious Azure Sign-ins Report - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}"
            
            # Add body
            body = f"""
            Suspicious Azure Sign-ins Report
            
            This automated report contains details of potentially suspicious Azure sign-ins.
            Please review the attached CSV file for details.
            
            Total suspicious sign-ins: {suspicious_count}
            Report generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            msg.attach(MIMEText(body, 'plain'))
            
            # Attach file
            attachment = open(report_path, "rb")
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f"attachment; filename={os.path.basename(report_path)}")
            msg.attach(part)
            
            # Send email
            server = smtplib.SMTP(self.config['smtp_server'], self.config['smtp_port'])
            server.starttls()
            server.login(self.config['smtp_username'], self.config['smtp_password'])
            server.send_message(msg)
            server.quit()
            
            print("Report email sent successfully")
            email_success = True
            
        except Exception as e:
            print(f"Error sending email: {e}")
            
        # Send Teams notification if enabled and requested
        if self.config["teams_notification"] and include_teams_notification:
            teams_success = self.send_teams_notification(report_path, summary_text, suspicious_logins)
            
        # Return true if at least one notification method succeeded
        return email_success or teams_success
        
    def _get_location_coordinates(self, location_info):
        """Get coordinates for a location using a geocoding service
        
        This function first checks if the location_info already has coordinates.
        If not, it falls back to a lookup table of major cities.
        
        Args:
            location_info: Dictionary with location information
            
        Returns:
            Tuple of (latitude, longitude) or None if not available
        """
        # First check if we already have coordinates in the location_info
        if location_info.get('latitude') is not None and location_info.get('longitude') is not None:
            try:
                latitude = float(location_info.get('latitude'))
                longitude = float(location_info.get('longitude'))
                return (latitude, longitude)
            except (ValueError, TypeError):
                # If conversion to float fails, continue to fallback method
                pass
                
        # Fall back to lookup table if coordinates not directly available
        city = location_info.get('city', '').lower()
        state = location_info.get('state', '').lower()
        country = location_info.get('country', '').lower()
        
        # Simple lookup table for common locations
        # These are approximate coordinates for major cities
        location_coords = {
            # US Cities
            ('new york', 'new york', 'us'): (40.7128, -74.0060),
            ('new york', 'ny', 'us'): (40.7128, -74.0060),
            ('los angeles', 'california', 'us'): (34.0522, -118.2437),
            ('los angeles', 'ca', 'us'): (34.0522, -118.2437),
            ('chicago', 'illinois', 'us'): (41.8781, -87.6298),
            ('chicago', 'il', 'us'): (41.8781, -87.6298),
            ('houston', 'texas', 'us'): (29.7604, -95.3698),
            ('houston', 'tx', 'us'): (29.7604, -95.3698),
            ('phoenix', 'arizona', 'us'): (33.4484, -112.0740),
            ('phoenix', 'az', 'us'): (33.4484, -112.0740),
            ('philadelphia', 'pennsylvania', 'us'): (39.9526, -75.1652),
            ('philadelphia', 'pa', 'us'): (39.9526, -75.1652),
            ('san antonio', 'texas', 'us'): (29.4241, -98.4936),
            ('san antonio', 'tx', 'us'): (29.4241, -98.4936),
            ('san diego', 'california', 'us'): (32.7157, -117.1611),
            ('san diego', 'ca', 'us'): (32.7157, -117.1611),
            ('dallas', 'texas', 'us'): (32.7767, -96.7970),
            ('dallas', 'tx', 'us'): (32.7767, -96.7970),
            ('san jose', 'california', 'us'): (37.3382, -121.8863),
            ('san jose', 'ca', 'us'): (37.3382, -121.8863),
            ('austin', 'texas', 'us'): (30.2672, -97.7431),
            ('austin', 'tx', 'us'): (30.2672, -97.7431),
            ('jacksonville', 'florida', 'us'): (30.3322, -81.6557),
            ('jacksonville', 'fl', 'us'): (30.3322, -81.6557),
            ('fort worth', 'texas', 'us'): (32.7555, -97.3308),
            ('fort worth', 'tx', 'us'): (32.7555, -97.3308),
            ('columbus', 'ohio', 'us'): (39.9612, -82.9988),
            ('columbus', 'oh', 'us'): (39.9612, -82.9988),
            ('indianapolis', 'indiana', 'us'): (39.7684, -86.1581),
            ('indianapolis', 'in', 'us'): (39.7684, -86.1581),
            ('charlotte', 'north carolina', 'us'): (35.2271, -80.8431),
            ('charlotte', 'nc', 'us'): (35.2271, -80.8431),
            ('seattle', 'washington', 'us'): (47.6062, -122.3321),
            ('seattle', 'wa', 'us'): (47.6062, -122.3321),
            ('denver', 'colorado', 'us'): (39.7392, -104.9903),
            ('denver', 'co', 'us'): (39.7392, -104.9903),
            ('washington', 'district of columbia', 'us'): (38.9072, -77.0369),
            ('washington', 'dc', 'us'): (38.9072, -77.0369),
            ('boston', 'massachusetts', 'us'): (42.3601, -71.0589),
            ('boston', 'ma', 'us'): (42.3601, -71.0589),
            ('nashville', 'tennessee', 'us'): (36.1627, -86.7816),
            ('nashville', 'tn', 'us'): (36.1627, -86.7816),
            ('baltimore', 'maryland', 'us'): (39.2904, -76.6122),
            ('baltimore', 'md', 'us'): (39.2904, -76.6122),
            ('saint louis', 'missouri', 'us'): (38.6270, -90.1994),
            ('st louis', 'missouri', 'us'): (38.6270, -90.1994),
            ('st. louis', 'missouri', 'us'): (38.6270, -90.1994),
            ('saint louis', 'mo', 'us'): (38.6270, -90.1994),
            ('st louis', 'mo', 'us'): (38.6270, -90.1994),
            ('st. louis', 'mo', 'us'): (38.6270, -90.1994),
            ('alpharetta', 'georgia', 'us'): (34.0754, -84.2941),
            ('alpharetta', 'ga', 'us'): (34.0754, -84.2941),
            ('atlanta', 'georgia', 'us'): (33.7490, -84.3880),
            ('atlanta', 'ga', 'us'): (33.7490, -84.3880),
            ('acworth', 'georgia', 'us'): (34.0659, -84.6769),
            ('acworth', 'ga', 'us'): (34.0659, -84.6769),
            ('ashburn', 'virginia', 'us'): (39.0438, -77.4874),
            ('ashburn', 'va', 'us'): (39.0438, -77.4874),
            ('chattanooga', 'tennessee', 'us'): (35.0456, -85.3097),
            ('chattanooga', 'tn', 'us'): (35.0456, -85.3097),
            ('ringgold', 'georgia', 'us'): (34.9160, -85.1091),
            ('ringgold', 'ga', 'us'): (34.9160, -85.1091),

            # International Cities
            ('london', '', 'gb'): (51.5074, -0.1278),
            ('paris', '', 'fr'): (48.8566, 2.3522),
            ('tokyo', '', 'jp'): (35.6762, 139.6503),
            ('sydney', '', 'au'): (33.8688, 151.2093),
            ('mexico city', '', 'mx'): (19.4326, -99.1332),
            ('berlin', '', 'de'): (52.5200, 13.4050),
            ('madrid', '', 'es'): (40.4168, -3.7038),
            ('rome', '', 'it'): (41.9028, 12.4964),
            ('toronto', '', 'ca'): (43.6532, -79.3832),
            ('beijing', '', 'cn'): (39.9042, 116.4074),
            ('dubai', '', 'ae'): (25.2048, 55.2708),
            ('frankfurt am main', 'hessen', 'de'): (50.1109, 8.6821),
            ('frankfurt', 'hessen', 'de'): (50.1109, 8.6821),
        }
        
        # Try to find an exact match first
        coords = location_coords.get((city, state, country))
        if coords:
            return coords
            
        # Try with just city and country
        coords = location_coords.get((city, '', country))
        if coords:
            return coords
            
        # If we can't find coordinates, return None (no need to log every miss)
        return None
        
    def _calculate_travel_distance(self, from_location, to_location):
        """Calculate the straight-line distance between two locations in miles
        
        Args:
            from_location: Dictionary with from location info
            to_location: Dictionary with to location info
            
        Returns:
            Distance in miles or None if calculation not possible
        """
        from_coords = self._get_location_coordinates(from_location)
        to_coords = self._get_location_coordinates(to_location)
        
        if not from_coords or not to_coords:
            return None
            
        # Calculate distance using geodesic (great circle) distance
        distance_km = geodesic(from_coords, to_coords).kilometers
        distance_miles = distance_km * 0.621371  # Convert km to miles
        
        return distance_miles
        
    def _calculate_travel_time_hours(self, from_timestamp, to_timestamp):
        """Calculate the time difference between two timestamps in hours
        
        Args:
            from_timestamp: Starting timestamp
            to_timestamp: Ending timestamp
            
        Returns:
            Time difference in hours
        """
        from_dt = datetime.datetime.strptime(from_timestamp, "%Y-%m-%d %H:%M:%S")
        to_dt = datetime.datetime.strptime(to_timestamp, "%Y-%m-%d %H:%M:%S")
        
        # Calculate time difference in hours
        time_diff = (to_dt - from_dt).total_seconds() / 3600
        
        return time_diff

    def detect_impossible_travel(self, logins):
        """Detect impossible travel between adjacent login locations
        
        Args:
            logins: List of login records (should be for a single user)
            
        Returns:
            Dictionary mapping login request IDs to impossible travel details
        """
        if not logins or len(logins) < 2:
            return {}
            
        # Sort logins by timestamp to ensure chronological order
        sorted_logins = sorted(logins, key=lambda x: x.get('timestamp', ''))
        
        impossible_travel_results = {}
        exempt_apps = [app.strip() for app in self.config["impossible_travel_exempt_apps"] if app.strip()]
        
        print(f"Checking impossible travel on {len(sorted_logins)} logins...")
        coord_available_count = 0
        coord_missing_count = 0
        below_min_distance_count = 0
        
        # Compare adjacent logins
        for i in range(1, len(sorted_logins)):
            from_login = sorted_logins[i-1]
            to_login = sorted_logins[i]
            
            # Skip if the from_login application is in the exempt list
            if from_login.get('application', '') in exempt_apps:
                continue
                
            # Skip if locations are identical
            from_location = from_login.get('location', '')
            to_location = to_login.get('location', '')
            if from_location == to_location:
                continue
                
            # Create location dictionaries for distance calculation
            from_loc_info = {
                'city': from_login.get('city', ''),
                'state': from_login.get('state', ''),
                'country': from_login.get('country', ''),
                'latitude': from_login.get('latitude'),
                'longitude': from_login.get('longitude')
            }
            
            to_loc_info = {
                'city': to_login.get('city', ''),
                'state': to_login.get('state', ''),
                'country': to_login.get('country', ''),
                'latitude': to_login.get('latitude'),
                'longitude': to_login.get('longitude')
            }
            
            # Calculate distance
            distance_miles = self._calculate_travel_distance(from_loc_info, to_loc_info)
            
            # Count coordinate availability
            has_coords = (from_loc_info.get('latitude') is not None and 
                         from_loc_info.get('longitude') is not None and
                         to_loc_info.get('latitude') is not None and
                         to_loc_info.get('longitude') is not None)
            
            if has_coords:
                coord_available_count += 1
            elif distance_miles is None:
                coord_missing_count += 1
                continue  # Skip if distance calculation failed
            
            # Skip if distance is below minimum threshold
            if not distance_miles or distance_miles < self.config["min_travel_distance_miles"]:
                below_min_distance_count += 1
                continue
                
            # Calculate time difference
            from_timestamp = from_login.get('timestamp', '')
            to_timestamp = to_login.get('timestamp', '')
            time_diff_hours = self._calculate_travel_time_hours(from_timestamp, to_timestamp)
            
            # Skip if time difference is negative or zero
            if time_diff_hours <= 0:
                continue
                
            # Calculate travel speed
            travel_speed = distance_miles / time_diff_hours
            
            # Check if travel speed exceeds maximum possible travel speed
            if travel_speed > self.config["max_travel_speed_mph"]:
                # Format impossible travel details
                impossible_travel_details = {
                    'from_location': from_location,
                    'to_location': to_location,
                    'distance_miles': round(distance_miles, 2),
                    'time_diff_hours': round(time_diff_hours, 2),
                    'travel_speed_mph': round(travel_speed, 2),
                    'from_timestamp': from_timestamp,
                    'from_request_id': from_login.get('request_id', '')
                }
                
                # Store result using the "to" login request ID as the key
                impossible_travel_results[to_login.get('request_id', '')] = impossible_travel_details
                
        # Print summary statistics
        print(f"Impossible travel analysis results:")
        print(f"  - Logins with coordinates: {coord_available_count}")
        print(f"  - Logins missing coordinates: {coord_missing_count}")
        print(f"  - Location pairs below minimum distance: {below_min_distance_count}")
        print(f"  - Impossible travel patterns detected: {len(impossible_travel_results)}")
                
        return impossible_travel_results

    def get_user_login_history(self, user_email):
        """Get historical login records for a specific user
        
        Args:
            user_email: User email to retrieve history for
            
        Returns:
            List of login records for the user
        """
        user_logins = []
        
        if not os.path.exists(self.login_history_path):
            print(f"Login history file not found at {self.login_history_path}")
            return user_logins
            
        try:
            with open(self.login_history_path, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    if row.get("user_email", "").lower() == user_email.lower():
                        user_logins.append(row)
                        
            print(f"Retrieved {len(user_logins)} historical login records for {user_email}")
            return user_logins
            
        except Exception as e:
            print(f"Error retrieving login history for {user_email}: {e}")
            return []

    def send_teams_notification(self, report_path, summary_text=None, suspicious_logins=None):
        """Send a Teams notification with a summary of suspicious logins
        
        Args:
            report_path: Path to the CSV report file
            summary_text: Optional summary text to include
            suspicious_logins: Optional list of suspicious login records to display in the card
        
        Returns:
            True if successful, False otherwise
        """
        if not self.config["teams_notification"] or not self.config["teams_webhook_url"]:
            print("Teams notification is disabled or webhook URL is not set")
            return False
            
        webhook_url = self.config["teams_webhook_url"]
        print(f"Using Teams webhook URL: {webhook_url}")
        
        try:
            # Read CSV file to extract suspicious logins count if not provided
            suspicious_count = 0
            if suspicious_logins:
                suspicious_count = len(suspicious_logins)
            else:
                with open(report_path, 'r', newline='', encoding='utf-8') as csvfile:
                    reader = csv.DictReader(csvfile)
                    suspicious_count = sum(1 for _ in reader)
                    
            if suspicious_count == 0:
                print("No suspicious logins to report to Teams")
                return False
                
            # Create summary
            if not summary_text:
                summary_text = f"Detected {suspicious_count} suspicious sign-ins"
                
            # Upload the CSV file to the Teams channel
            file_url = None
            if self.config["teams_notification"]:
                file_url = self.upload_file_to_teams(report_path)
            
            # Create a very simple adaptive card with just the alert info
            card_body = [
                {
                    "type": "TextBlock",
                    "text": "Suspicious Sign-in Alert",
                    "weight": "bolder",
                    "size": "medium"
                },
                {
                    "type": "TextBlock",
                    "text": summary_text,
                    "wrap": True
                }
            ]
            
            # Add file link if available
            if file_url:
                card_body.append({
                    "type": "TextBlock",
                    "text": "See attached report for details:",
                    "wrap": True
                })
                card_body.append({
                    "type": "ActionSet",
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "View CSV Report",
                            "url": file_url
                        }
                    ]
                })
            
            # Add suspicious login details directly to the card if available
            if suspicious_logins:
                # Add a divider
                card_body.append({
                    "type": "FactSet",
                    "facts": [
                        {
                            "title": "Suspicious Sign-in Details:",
                            "value": " "
                        }
                    ]
                })
                
                # Limit to max 10 logins to avoid oversized cards
                for i, login in enumerate(suspicious_logins[:10]):
                    user = login.get("user_email", "Unknown user")
                    timestamp = login.get("timestamp", "Unknown time")
                    location = login.get("location", "Unknown location")
                    ip_address = login.get("ip_address", "Unknown IP")
                    application = login.get("application", "Unknown app")
                    reasons = login.get("reasons", "Unknown reason")
                    
                    # Get device information if available
                    device_id = login.get("device_id", "")
                    device_name = login.get("device_name", "")
                    device_fingerprint = login.get("device_fingerprint", "")
                    
                    # Only include top 10 logins to avoid oversized cards
                    if i < 10:
                        fact_content = f"**User:** {user}\n**Time:** {timestamp}\n**Location:** {location}\n" \
                                    f"**IP:** {ip_address}\n**App:** {application}"
                        
                        # Add device information if available
                        if device_id:
                            fact_content += f"\n**Device ID:** {device_id}"
                        if device_name:
                            fact_content += f"\n**Device Name:** {device_name}"
                        if device_fingerprint:
                            fact_content += f"\n**Device Fingerprint:** {device_fingerprint}"
                            
                        # Add reason at the end
                        fact_content += f"\n**Reason:** {reasons}"
                        
                        card_body.append({
                            "type": "TextBlock",
                            "text": f"Sign-in {i+1}:",
                            "weight": "bolder",
                            "spacing": "medium"
                        })
                        card_body.append({
                            "type": "TextBlock",
                            "text": fact_content,
                            "wrap": True,
                            "spacing": "small"
                        })
                
                # Add a note if there are more than 10 suspicious logins
                if len(suspicious_logins) > 10:
                    card_body.append({
                        "type": "TextBlock",
                        "text": f"... and {len(suspicious_logins) - 10} more suspicious sign-ins. See the full report for details.",
                        "wrap": True,
                        "spacing": "medium",
                        "weight": "bolder"
                    })
            
            # Create payload using the exact format from your successful test
            payload = {
                "text": summary_text,  # Fallback text
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "content": {
                            "type": "AdaptiveCard",
                            "version": "1.0",
                            "body": card_body
                        }
                    }
                ]
            }
            
            # Send to Teams webhook
            headers = {
                "Content-Type": "application/json"
            }
            
            print("Making POST request to Teams webhook URL...")
            response = requests.post(webhook_url, headers=headers, json=payload)
            
            if response.status_code < 200 or response.status_code >= 300:
                print(f"Error sending Teams notification: {response.status_code} - {response.text}")
                return False
                
            print(f"Teams notification sent successfully")
            return True
            
        except Exception as e:
            print(f"Error sending Teams notification: {str(e)}")
            traceback.print_exc()
            return False

    def upload_file_to_teams(self, file_path):
        """Upload a file to the Teams channel's Files tab
        
        Args:
            file_path: Path to the file to upload
            
        Returns:
            URL to the uploaded file or None if upload failed
        """
        if not os.path.exists(file_path):
            print(f"Error: File not found at {file_path}")
            return None
            
        if not self.config["teams_notification"]:
            print("Teams notification is disabled")
            return None
            
        try:
            # Get auth token (reuse existing method for Graph API)
            token = self.get_auth_token()
            
            # Set up headers
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            # Get file name and prepare file content
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            print(f"Uploading {file_name} ({file_size} bytes) to Teams channel...")
            
            # Step 1: Create upload session
            # Build the URL for the channel's drive items
            group_id = self.config["teams_group_id"]
            channel_id = self.config["teams_channel_id"]
            
            # First, get the channel's drive and folder ID
            drive_url = f"https://graph.microsoft.com/v1.0/teams/{group_id}/channels/{channel_id}/filesFolder"
            response = requests.get(drive_url, headers=headers)
            
            if response.status_code != 200:
                print(f"Error getting channel drive info: {response.status_code} - {response.text}")
                return None
                
            drive_info = response.json()
            parent_reference = drive_info.get("parentReference", {})
            drive_id = parent_reference.get("driveId")
            item_id = drive_info.get("id")
            
            if not drive_id or not item_id:
                print("Could not get channel drive info")
                return None
                
            # Create an upload session
            upload_url = f"https://graph.microsoft.com/v1.0/drives/{drive_id}/items/{item_id}:/{file_name}:/createUploadSession"
            upload_data = {
                "item": {
                    "@microsoft.graph.conflictBehavior": "rename"
                }
            }
            
            response = requests.post(upload_url, headers=headers, json=upload_data)
            
            if response.status_code != 200:
                print(f"Error creating upload session: {response.status_code} - {response.text}")
                return None
                
            upload_session = response.json()
            upload_url = upload_session.get("uploadUrl")
            
            if not upload_url:
                print("Could not get upload URL")
                return None
                
            # Step 2: Upload file content with proper chunking
            # Use 4MB chunks as recommended by Microsoft for Graph API
            CHUNK_SIZE = 4 * 1024 * 1024  # 4 MB in bytes
            
            # Read the whole file if it's small, or handle in chunks if large
            with open(file_path, 'rb') as file:
                # For small files, do a single upload
                if file_size <= CHUNK_SIZE:
                    file_content = file.read()
                    
                    # Upload with the proper Content-Range header
                    upload_headers = {
                        'Content-Length': str(file_size),
                        'Content-Range': f'bytes 0-{file_size-1}/{file_size}'
                    }
                    
                    # Upload the file content
                    response = requests.put(upload_url, headers=upload_headers, data=file_content)
                    
                    if response.status_code >= 200 and response.status_code < 300:
                        uploaded_file = response.json()
                        web_url = uploaded_file.get("webUrl")
                        
                        print(f"File uploaded successfully: {web_url}")
                        return web_url
                    else:
                        print(f"Error uploading file: {response.status_code} - {response.text}")
                        return None
                
                # For larger files, upload in chunks
                else:
                    # Initialize upload state
                    uploaded = 0
                    file_content = None
                    
                    while uploaded < file_size:
                        # Calculate chunk size for this iteration
                        chunk_size = min(CHUNK_SIZE, file_size - uploaded)
                        
                        # Read the chunk
                        chunk = file.read(chunk_size)
                        
                        # Calculate range for this chunk
                        chunk_start = uploaded
                        chunk_end = uploaded + chunk_size - 1
                        
                        # Prepare headers for this chunk
                        upload_headers = {
                            'Content-Length': str(chunk_size),
                            'Content-Range': f'bytes {chunk_start}-{chunk_end}/{file_size}'
                        }
                        
                        # Upload the chunk
                        chunk_response = requests.put(upload_url, headers=upload_headers, data=chunk)
                        
                        # Check if upload succeeded
                        if chunk_response.status_code not in [200, 201, 202, 204]:
                            print(f"Chunk upload failed: {chunk_response.status_code} - {chunk_response.text}")
                            return None
                        
                        # Update uploaded amount
                        uploaded += chunk_size
                        
                        # Print progress for large files
                        print(f"Uploaded {uploaded}/{file_size} bytes ({(uploaded/file_size)*100:.1f}%)")
                        
                        # If this was the last chunk, the response will contain the file info
                        if uploaded >= file_size:
                            try:
                                uploaded_file = chunk_response.json()
                                web_url = uploaded_file.get("webUrl")
                                
                                print(f"File uploaded successfully: {web_url}")
                                return web_url
                            except:
                                # If we can't parse the response, try getting the file directly
                                file_url = f"https://graph.microsoft.com/v1.0/drives/{drive_id}/root:/{file_name}"
                                file_response = requests.get(file_url, headers={'Authorization': f'Bearer {token}'})
                                
                                if file_response.status_code == 200:
                                    file_data = file_response.json()
                                    web_url = file_data.get("webUrl")
                                    print(f"File uploaded successfully: {web_url}")
                                    return web_url
                        
                    # If we reach here without returning, something went wrong
                    print("File upload completed but couldn't get file URL")
                    return None
                
        except Exception as e:
            print(f"Error uploading file to Teams: {e}")
            return None

    def analyze_device_fingerprints(self):
        """Analyze device fingerprints to identify safe devices that meet criteria:
        - Multiple appearances (3+ logins)
        - Used across multiple days (7+ day span)
        - Consistently associated with same user
        - Connected from known user locations
        
        Returns:
            Set of device fingerprints that meet criteria
        """
        print("Analyzing device fingerprints for whitelist...")
        
        if not os.path.exists(self.login_history_path):
            print(f"Error: Login history file not found at {self.login_history_path}")
            return set()
        
        # Track fingerprint usage data
        fingerprint_data = {}  # Stores comprehensive data about each fingerprint
        
        try:
            with open(self.login_history_path, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                
                for row in reader:
                    fingerprint = row.get("device_fingerprint", "")
                    user_email = row.get("user_email", "").lower()
                    location = row.get("location", "")
                    timestamp_str = row.get("timestamp", "")
                    
                    # Skip records without fingerprint or user email
                    if not fingerprint or not user_email or not timestamp_str:
                        continue
                    
                    # Parse timestamp to extract date
                    try:
                        dt = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        login_date = dt.date()
                    except:
                        # Skip if timestamp can't be parsed
                        continue
                    
                    # Initialize tracking for new fingerprints
                    if fingerprint not in fingerprint_data:
                        fingerprint_data[fingerprint] = {
                            "users": set(),
                            "locations": set(),
                            "dates": set(),
                            "login_count": 0,
                            "first_seen": login_date,
                            "last_seen": login_date
                        }
                    
                    # Update fingerprint data
                    data = fingerprint_data[fingerprint]
                    data["users"].add(user_email)
                    if location:
                        data["locations"].add(location)
                    data["dates"].add(login_date)
                    data["login_count"] += 1
                    
                    # Update first/last seen
                    if login_date < data["first_seen"]:
                        data["first_seen"] = login_date
                    if login_date > data["last_seen"]:
                        data["last_seen"] = login_date
            
            # Apply criteria to identify safe fingerprints
            min_logins = self.config["device_fingerprint_min_logins"]
            min_days_span = self.config["device_fingerprint_min_days"]
            
            safe_fingerprints = set()
            
            for fingerprint, data in fingerprint_data.items():
                # Get user's safe locations if available
                user_emails = data["users"]
                if len(user_emails) != 1:
                    # Skip if used by multiple users
                    print(f"  Fingerprint {fingerprint}: Used by multiple users ({len(user_emails)}), not whitelisting")
                    continue
                
                user_email = next(iter(user_emails))
                user_whitelist = self.whitelists.get(user_email, {})
                safe_user_locations = set()
                
                if user_whitelist and "locations" in user_whitelist:
                    if isinstance(user_whitelist["locations"], list):
                        # Handle list format (older version)
                        for loc_data in user_whitelist["locations"]:
                            if isinstance(loc_data, dict) and "location" in loc_data:
                                safe_user_locations.add(loc_data["location"])
                    elif isinstance(user_whitelist["locations"], dict):
                        # Handle dict format
                        safe_user_locations = set(user_whitelist["locations"].keys())
                
                # Check criteria
                login_count = data["login_count"]
                day_span = (data["last_seen"] - data["first_seen"]).days + 1
                locations = data["locations"]
                
                # Check locations against user's safe locations
                locations_known = False
                if safe_user_locations:
                    # Check if any fingerprint locations match user's safe locations
                    locations_known = any(loc in safe_user_locations for loc in locations)
                
                # Apply the criteria
                if (login_count >= min_logins and 
                    day_span >= min_days_span and 
                    len(user_emails) == 1 and
                    (not safe_user_locations or locations_known)):
                    
                    safe_fingerprints.add(fingerprint)
                    print(f"  Whitelisted fingerprint {fingerprint}")
                    print(f"    User: {user_email}")
                    print(f"    Logins: {login_count}")
                    print(f"    Day span: {day_span} days")
                    print(f"    Locations: {', '.join(locations)}")
                else:
                    # For debugging, print why it wasn't whitelisted
                    reasons = []
                    if login_count < min_logins:
                        reasons.append(f"insufficient logins ({login_count} < {min_logins})")
                    if day_span < min_days_span:
                        reasons.append(f"insufficient day span ({day_span} < {min_days_span})")
                    if len(user_emails) != 1:
                        reasons.append("multiple users")
                    if safe_user_locations and not locations_known:
                        reasons.append("no known locations")
                    
                    if login_count >= 2:  # Only log if it had multiple logins
                        print(f"  Not whitelisting fingerprint {fingerprint}: {', '.join(reasons)}")
            
            # Save the whitelist
            self.save_fingerprint_whitelist(safe_fingerprints)
            
            print(f"Fingerprint analysis complete. Whitelisted {len(safe_fingerprints)} fingerprints.")
            return safe_fingerprints
            
        except Exception as e:
            print(f"Error analyzing device fingerprints: {e}")
            traceback.print_exc()
            return set()
    
    def save_fingerprint_whitelist(self, fingerprints):
        """Save device fingerprint whitelist to file
        
        Args:
            fingerprints: Set of whitelisted fingerprints
        """
        whitelist_data = {
            "fingerprints": list(fingerprints),
            "generated_at": datetime.datetime.now().isoformat(),
            "criteria": {
                "min_logins": self.config["device_fingerprint_min_logins"],
                "min_days": self.config["device_fingerprint_min_days"]
            }
        }
        
        try:
            with open(self.fingerprint_whitelist_path, 'w') as file:
                json.dump(whitelist_data, file, indent=2)
            print(f"Device fingerprint whitelist saved to {self.fingerprint_whitelist_path}")
            
            # Update instance variable
            self.fingerprint_whitelist = fingerprints
        except Exception as e:
            print(f"Error saving device fingerprint whitelist: {e}")
    
    def load_fingerprint_whitelist(self):
        """Load device fingerprint whitelist from file
        
        Returns:
            Set of whitelisted device fingerprints
        """
        if not os.path.exists(self.fingerprint_whitelist_path):
            print(f"Device fingerprint whitelist file not found at {self.fingerprint_whitelist_path}")
            return set()
            
        try:
            with open(self.fingerprint_whitelist_path, 'r') as file:
                whitelist_data = json.load(file)
                
            fingerprints = set(whitelist_data.get("fingerprints", []))
            print(f"Loaded {len(fingerprints)} whitelisted device fingerprints")
            
            # Update instance variable
            self.fingerprint_whitelist = fingerprints
            
            return fingerprints
        except Exception as e:
            print(f"Error loading device fingerprint whitelist: {e}")
            return set()

    def update_whitelists_for_users(self, processed_records):
        """Update whitelists for users with new sign-ins
        
        This method updates:
        1. User location whitelists - Adds new qualifying locations to user whitelists
        2. Device fingerprint whitelist - Adds new qualifying fingerprints
        
        Args:
            processed_records: List of processed sign-in records from recent polling
            
        Returns:
            Tuple of (updated_locations_count, updated_fingerprints_count)
        """
        if not self.config.get("retroactive_location_whitelist_updates", True) and not self.config.get("retroactive_fingerprint_whitelist_updates", True):
            return 0, 0
            
        print("Checking for whitelist updates...")
        
        # Get unique users from the processed records
        user_emails = set()
        for record in processed_records:
            if isinstance(record, dict) and "user_email" in record:
                user_emails.add(record.get("user_email", "").lower())
        
        if not user_emails:
            print("No users found in the new sign-ins")
            return 0, 0
            
        updated_locations_count = 0
        updated_fingerprints_count = 0
        
        # Track detailed update information
        location_updates_by_user = {}
        fingerprint_updates_by_user = {}
        
        # Process each user
        for user_email in user_emails:
            try:
                # Skip empty email
                if not user_email:
                    continue
                    
                print(f"Checking whitelist updates for user: {user_email}")
                
                # 1. Update user location whitelist if enabled
                if self.config.get("retroactive_location_whitelist_updates", True):
                    locations_added, location_details = self._update_user_location_whitelist(user_email)
                    updated_locations_count += locations_added
                    
                    if locations_added > 0:
                        location_updates_by_user[user_email] = location_details
                
                # 2. Update fingerprint whitelist if enabled
                if self.config.get("retroactive_fingerprint_whitelist_updates", True):
                    # Find fingerprints used by this user in new records
                    user_fingerprints = set()
                    for record in processed_records:
                        if (isinstance(record, dict) and 
                            record.get("user_email", "").lower() == user_email and 
                            "device_fingerprint" in record and 
                            record["device_fingerprint"]):
                            user_fingerprints.add(record["device_fingerprint"])
                    
                    if user_fingerprints:
                        fingerprints_added, fingerprint_details = self._update_user_fingerprint_whitelist(user_email, user_fingerprints)
                        updated_fingerprints_count += fingerprints_added
                        
                        if fingerprints_added > 0:
                            fingerprint_updates_by_user[user_email] = fingerprint_details
            
            except Exception as e:
                print(f"Error updating whitelists for user {user_email}: {e}")
                # Continue with next user
        
        print(f"Whitelist updates completed.")
        
        # Print a summary of the whitelist updates
        if updated_locations_count > 0 or updated_fingerprints_count > 0:
            print("\n===== WHITELIST UPDATES SUMMARY =====")
            if updated_locations_count > 0:
                print(f"LOCATION WHITELIST UPDATES: {updated_locations_count} new locations added")
                for user, locations in location_updates_by_user.items():
                    print(f"  User: {user}")
                    for location in locations:
                        print(f"    + {location['location']} ({location['count']} logins, {location['percentage']:.1f}%)")
            
            if updated_fingerprints_count > 0:
                print(f"FINGERPRINT WHITELIST UPDATES: {updated_fingerprints_count} new fingerprints added")
                for user, fingerprints in fingerprint_updates_by_user.items():
                    print(f"  User: {user}")
                    for fingerprint in fingerprints:
                        print(f"    + {fingerprint['id']} ({fingerprint['login_count']} logins, {fingerprint['day_span']} days)")
            print("======================================\n")
        else:
            print("No whitelist updates were made in this batch.")
            
        return updated_locations_count, updated_fingerprints_count
    
    def _update_user_location_whitelist(self, user_email):
        """Update location whitelist for a specific user
        
        Args:
            user_email: Email of the user to update
            
        Returns:
            Tuple of (number of new locations added, list of location details)
        """
        try:
            # Get user's full login history
            user_logins = self.get_user_login_history(user_email)
            
            if len(user_logins) < 3:
                print(f"Not enough login data for {user_email} to update location whitelist (minimum 3 required)")
                return 0, []
            
            # Count locations (same logic as in build_whitelist)
            location_count = {}
            for login in user_logins:
                location = login.get("location", "")
                
                if not location:
                    continue
                    
                if location not in location_count:
                    location_count[location] = 0
                    
                location_count[location] += 1
            
            # Calculate location threshold
            total_logins = len(user_logins)
            location_threshold = max(2, int(total_logins * self.config["location_frequency_threshold"]))
            
            # Get current whitelist for this user
            if not self.whitelists:
                self.load_whitelist()
                
            user_whitelist = self.whitelists.get(user_email, {})
            
            # Initialize if user doesn't have a whitelist yet
            if not user_whitelist:
                user_whitelist = {
                    "locations": [],
                    "work_hours": [8, 18],  # Default work hours
                    "international_user": False
                }
            
            # Get existing safe locations
            safe_locations = []
            existing_location_names = set()
            
            # Handle both list and dict format for backwards compatibility
            if "locations" in user_whitelist:
                if isinstance(user_whitelist["locations"], list):
                    safe_locations = user_whitelist["locations"]
                    existing_location_names = {loc["location"] for loc in safe_locations if isinstance(loc, dict) and "location" in loc}
                elif isinstance(user_whitelist["locations"], dict):
                    for location, data in user_whitelist["locations"].items():
                        safe_locations.append({
                            "location": location,
                            "count": data,
                            "percentage": (data / total_logins) * 100 if total_logins > 0 else 0
                        })
                    existing_location_names = set(user_whitelist["locations"].keys())
            
            # Find new safe locations
            new_locations_added = 0
            new_location_details = []
            
            for location, count in location_count.items():
                if location and location not in existing_location_names and count >= location_threshold:
                    # Add new location that meets threshold
                    percentage = (count / total_logins) * 100
                    location_detail = {
                        "location": location,
                        "count": count,
                        "percentage": percentage
                    }
                    safe_locations.append(location_detail)
                    new_location_details.append(location_detail)
                    print(f"Added location {location} to whitelist for {user_email} " +
                          f"({count}/{total_logins} logins, {percentage:.1f}%)")
                    new_locations_added += 1
                    existing_location_names.add(location)
            
            if new_locations_added > 0:
                # Convert to dict format for consistency
                locations_dict = {}
                for loc in safe_locations:
                    locations_dict[loc["location"]] = loc["count"]
                
                # Update user whitelist
                user_whitelist["locations"] = locations_dict
                self.whitelists[user_email] = user_whitelist
                
                # Save updated whitelist
                self.save_whitelist(self.whitelists)
            
            return new_locations_added, new_location_details
            
        except Exception as e:
            print(f"  Error updating location whitelist for {user_email}: {e}")
            return 0, []
    
    def _update_user_fingerprint_whitelist(self, user_email, fingerprints_to_check=None):
        """Update fingerprint whitelist based on a user's sign-ins
        
        Args:
            user_email: Email of the user to check
            fingerprints_to_check: Optional set of specific fingerprints to check
            
        Returns:
            Tuple of (number of new fingerprints added, list of fingerprint details)
        """
        try:
            # Skip if no fingerprints to check
            if fingerprints_to_check is not None and not fingerprints_to_check:
                return 0, []
            
            # Get all whitelisted fingerprints
            if not self.fingerprint_whitelist:
                self.load_fingerprint_whitelist()
                
            # Get user logins
            user_logins = self.get_user_login_history(user_email)
            
            if len(user_logins) < 3:
                print(f"Not enough login data for {user_email} to update fingerprint whitelist (minimum 3 required)")
                return 0, []
            
            # Track fingerprint data (similar logic to analyze_device_fingerprints)
            fingerprint_data = {}
            
            # Process each login
            for login in user_logins:
                fingerprint = login.get("device_fingerprint", "")
                location = login.get("location", "")
                timestamp_str = login.get("timestamp", "")
                
                # Skip records without fingerprint or timestamp
                if not fingerprint or not timestamp_str:
                    continue
                    
                # If we're only checking specific fingerprints, skip others
                if fingerprints_to_check is not None and fingerprint not in fingerprints_to_check:
                    continue
                
                # Parse timestamp to extract date
                try:
                    dt = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    login_date = dt.date()
                except:
                    # Skip if timestamp can't be parsed
                    continue
                
                # Initialize tracking for new fingerprints
                if fingerprint not in fingerprint_data:
                    fingerprint_data[fingerprint] = {
                        "users": set([user_email]),  # We already know the user
                        "locations": set(),
                        "dates": set(),
                        "login_count": 0,
                        "first_seen": login_date,
                        "last_seen": login_date
                    }
                
                # Update fingerprint data
                data = fingerprint_data[fingerprint]
                if location:
                    data["locations"].add(location)
                data["dates"].add(login_date)
                data["login_count"] += 1
                
                # Update first/last seen
                if login_date < data["first_seen"]:
                    data["first_seen"] = login_date
                if login_date > data["last_seen"]:
                    data["last_seen"] = login_date
            
            # Apply criteria to identify new safe fingerprints
            min_logins = self.config["device_fingerprint_min_logins"]
            min_days_span = self.config["device_fingerprint_min_days"]
            
            new_fingerprints = set()
            new_fingerprint_details = []
            
            # Get user's safe locations
            user_whitelist = self.whitelists.get(user_email, {})
            safe_user_locations = set()
            
            if user_whitelist and "locations" in user_whitelist:
                if isinstance(user_whitelist["locations"], list):
                    # Handle list format (older version)
                    for loc_data in user_whitelist["locations"]:
                        if isinstance(loc_data, dict) and "location" in loc_data:
                            safe_user_locations.add(loc_data["location"])
                elif isinstance(user_whitelist["locations"], dict):
                    # Handle dict format
                    safe_user_locations = set(user_whitelist["locations"].keys())
            
            # Check each fingerprint against criteria
            for fingerprint, data in fingerprint_data.items():
                # Skip if already whitelisted
                if fingerprint in self.fingerprint_whitelist:
                    continue
                    
                # Check criteria
                login_count = data["login_count"]
                day_span = (data["last_seen"] - data["first_seen"]).days + 1
                locations = data["locations"]
                
                # Check locations against user's safe locations
                locations_known = False
                if safe_user_locations:
                    # Check if any fingerprint locations match user's safe locations
                    locations_known = any(loc in safe_user_locations for loc in locations)
                
                # Apply the criteria
                if (login_count >= min_logins and 
                    day_span >= min_days_span and 
                    len(data["users"]) == 1 and
                    (not safe_user_locations or locations_known)):
                    
                    new_fingerprints.add(fingerprint)
                    print(f"Added fingerprint {fingerprint} to whitelist for {user_email}")
                    print(f"    User: {user_email}")
                    print(f"    Logins: {login_count}")
                    print(f"    Day span: {day_span} days")
                    print(f"    Locations: {', '.join(locations)}")
                    
                    # Create a detailed record for this fingerprint
                    fingerprint_detail = {
                        "id": fingerprint,
                        "login_count": login_count,
                        "day_span": day_span,
                        "locations": list(locations)
                    }
                    new_fingerprint_details.append(fingerprint_detail)
            
            # Update whitelist if we found new fingerprints
            if new_fingerprints:
                # Combine with existing fingerprints
                updated_fingerprints = self.fingerprint_whitelist.union(new_fingerprints)
                
                # Save the updated whitelist
                self.save_fingerprint_whitelist(updated_fingerprints)
                
                return len(new_fingerprints), new_fingerprint_details
            
            return 0, []
            
        except Exception as e:
            print(f"  Error updating fingerprint whitelist for {user_email}: {e}")
            return 0, []

    def log_excluded_alerts(self):
        """Log alerts that were excluded due to device-based exclusions
        
        This helps track and analyze potential alerts that were suppressed
        """
        if not self.excluded_alerts:
            print("No excluded alerts to log")
            return
        
        # Ensure Data directory exists
        os.makedirs(os.path.join(self.script_dir, "Data"), exist_ok=True)    
            
        print(f"Logging {len(self.excluded_alerts)} excluded alerts to {self.excluded_alerts_log_path}")
        
        # Double-check the excluded_alerts has content
        for alert in self.excluded_alerts[:3]:  # Print first 3 for debugging
            print(f"  Sample excluded alert: {alert.get('user_email')}, {alert.get('exclusion_reason')}")
            
        file_exists = os.path.exists(self.excluded_alerts_log_path)
        
        try:
            with open(self.excluded_alerts_log_path, 'a', newline='', encoding='utf-8') as csvfile:
                fieldnames = ["request_id", "timestamp", "user_email", "application", 
                             "ip_address", "location", "device_id", "device_name", 
                             "device_fingerprint", "browser", "os", "client_app", 
                             "reasons", "exclusion_reason"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                # Write header if file is new
                if not file_exists:
                    writer.writeheader()
                
                # Write excluded alerts
                for alert in self.excluded_alerts:
                    # Create a clean record with only the expected fields
                    clean_record = {}
                    for field in fieldnames:
                        clean_record[field] = alert.get(field, "")
                    
                    writer.writerow(clean_record)
                    
            print(f"Successfully logged {len(self.excluded_alerts)} excluded alerts to {self.excluded_alerts_log_path}")
        except Exception as e:
            print(f"Error logging excluded alerts: {e}")
            traceback.print_exc()  # Print stack trace for better debugging


if __name__ == "__main__":
    try:
        monitor = AzureSignInMonitor()
        monitor.run()
    except KeyboardInterrupt:
        print("\nScript interrupted by user. Exiting gracefully...")
        sys.exit(0)
    except Exception as e:
        print(f"Unhandled exception: {e}")
        sys.exit(1) 