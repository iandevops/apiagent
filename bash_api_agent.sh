#!/bin/bash

# Exit on any error
set -e

# --- Configuration Variables (Consider making these configurable or prompted) ---
API_USER="cpagentuser" # Username for the agent
APP_DIR="/opt/cpanel_agent"
VENV_DIR="$APP_DIR/venv"
FLASK_APP_PORT="5858" # Port for the Flask API to listen on (localhost)
LOG_FILE="$APP_DIR/agent.log"
DJANGO_SSH_PUBLIC_KEY="" # This will be prompted for

# --- Helper Functions ---
log_message() {
    echo "[INFO] $1"
}

log_error() {
    echo "[ERROR] $1" >&2
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root."
        exit 1
    fi
}

detect_os_and_install_python() {
    log_message "Detecting OS and checking for Python 3..."
    PYTHON_CMD="python3"
    PIP_CMD="pip3"

    if command -v python3 &>/dev/null; then
        log_message "Python 3 found: $(python3 --version)"
    else
        log_message "Python 3 not found. Attempting installation..."
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS=$NAME
            if [[ "$OS" == "Ubuntu" || "$OS" == "Debian GNU/Linux" ]]; then
                apt-get update
                apt-get install -y python3 python3-pip python3-venv
            elif [[ "$OS" == "CentOS Linux" || "$OS" == "AlmaLinux" || "$OS" == "Rocky Linux" || "$OS" == "Red Hat Enterprise Linux" ]]; then
                dnf install -y python3 python3-pip # or yum for older CentOS
                # python3-virtualenv might be needed or use python3 -m venv
            else
                log_error "Unsupported OS: $OS. Please install Python 3 and pip3 manually."
                exit 1
            fi
        else
            log_error "Cannot detect OS. Please install Python 3 and pip3 manually."
            exit 1
        fi
        log_message "Python 3 installed."
    fi

    if ! command -v $PIP_CMD &> /dev/null; then
         log_error "pip3 not found even after Python install. Please check."
         exit 1
    fi
}

create_api_user() {
    log_message "Creating API user: $API_USER..."
    if id "$API_USER" &>/dev/null; then
        log_message "User $API_USER already exists."
    else
        useradd -m -r -s /bin/bash "$API_USER" # -r for system account
        passwd -l "$API_USER" # Lock password login
        log_message "User $API_USER created."
    fi
}

setup_ssh_key() {
    log_message "Setting up SSH key for $API_USER..."
    read -p "Please paste the PUBLIC SSH key for Django to connect AS $API_USER (for future direct SSH use if any, not for Flask API auth): " DJANGO_SSH_PUBLIC_KEY
    if [ -z "$DJANGO_SSH_PUBLIC_KEY" ]; then
        log_error "No SSH public key provided. Skipping SSH key setup for direct access."
        # Decide if this is critical. If Flask API is the only interaction, direct SSH for Django might not be needed.
        # But it's good for the user account itself to be accessible via key.
        return
    fi

    local user_home
    user_home=$(eval echo ~$API_USER)
    mkdir -p "$user_home/.ssh"
    echo "$DJANGO_SSH_PUBLIC_KEY" > "$user_home/.ssh/authorized_keys"
    chown -R "$API_USER:$API_USER" "$user_home/.ssh"
    chmod 700 "$user_home/.ssh"
    chmod 600 "$user_home/.ssh/authorized_keys"
    log_message "SSH public key added for $API_USER."
}

configure_sudo() {
    log_message "Configuring sudo privileges for $API_USER..."
    # This is a critical step. Make rules as specific as possible.
    # For lvectl set-user, allowing specific arguments is safer but complex.
    # Example: Allow setting specific parameters. This gets very long.
    # A more general but still somewhat restricted rule:
    SUDO_RULE="$API_USER ALL=(ALL) NOPASSWD: /usr/sbin/lvectl set-user *"
    # You might need separate lines for each lvectl subcommand you want to allow later.
    # e.g. $API_USER ALL=(ALL) NOPASSWD: /usr/sbin/lvectl apply all

    echo "$SUDO_RULE" > "/etc/sudoers.d/90-$API_USER-agent"
    chmod 0440 "/etc/sudoers.d/90-$API_USER-agent"
    log_message "Sudo rule created: /etc/sudoers.d/90-$API_USER-agent"
    log_message "Rule content: $SUDO_RULE"
    log_message "Verifying sudoers syntax..."
    if visudo -c; then
        log_message "sudoers syntax check passed."
    else
        log_error "sudoers syntax check FAILED. Please review /etc/sudoers.d/90-$API_USER-agent manually."
        # Consider removing the bad file here: rm "/etc/sudoers.d/90-$API_USER-agent"
        exit 1
    fi
}

setup_flask_app() {
    log_message "Setting up Flask application in $APP_DIR..."
    mkdir -p "$APP_DIR"
    chown "$API_USER:$API_USER" "$APP_DIR" # Grant ownership to API user

    # Create Flask app file (app.py) - content will be defined in section II
    # For now, just create a placeholder or copy from a source
    sudo -u "$API_USER" "$PYTHON_CMD" -m venv "$VENV_DIR"
    log_message "Virtual environment created in $VENV_DIR."

    # Activate venv and install packages
    # Note: Running pip as another user requires careful handling of sudo -u or running this part as the user
    log_message "Installing Flask and Gunicorn..."
    sudo -u "$API_USER" "$VENV_DIR/bin/pip" install Flask gunicorn python-dotenv

    # Create a simple app.py, .env, and wsgi.py
    # app.py (actual content will be more complex - see section II)
    cat << EOF > "$APP_DIR/app.py"
import os
from flask import Flask, request, jsonify
import subprocess
import shlex
import logging
from functools import wraps
from dotenv import load_dotenv
from apscheduler.schedulers.background import BackgroundScheduler
import atexit # To ensure scheduler shuts down cleanly
import json
from datetime import datetime, timedelta
import glob
import time
import requests # For sending data to Django backend
import threading # For collection_lock

# Load environment variables from .env file in the same directory
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(dotenv_path)

app = Flask(__name__)

# --- Configuration ---
FLASK_HOST = os.getenv('FLASK_HOST', '127.0.0.1')
FLASK_PORT = int(os.getenv('FLASK_PORT', 5858))
LOG_FILE = os.getenv('LOG_FILE', 'agent.log') # Make sure this path is writable by the API_USER
API_KEY = os.getenv('API_KEY') # Loaded from .env

# --- New LVE Collection Configuration ---
LVE_COLLECTION_INTERVAL_SECONDS = int(os.getenv('LVE_COLLECTION_INTERVAL_SECONDS', 60)) # How often to trigger collection (e.g., every minute)
LVE_BATCH_DIVISOR = int(os.getenv('LVE_BATCH_DIVISOR', 3)) # Divide users into this many batches
LVE_FILE_LIFETIME_MINUTES = int(os.getenv('LVE_FILE_LIFETIME_MINUTES', 6)) # How long to keep temporary JSON files
LVE_DATA_DIR = os.getenv('LVE_DATA_DIR', '/tmp/lve_data') # Directory for temporary data files

# Django Backend API Configuration
DJANGO_API_BASE_URL = os.getenv('DJANGO_API_BASE_URL', 'http://localhost:8000/api/') # Ensure trailing slash
DJANGO_API_KEY_FOR_FLASK = os.getenv('DJANGO_API_KEY_FOR_FLASK') # API Key for Flask to authenticate with Django

# Create data directory if it doesn't exist
os.makedirs(LVE_DATA_DIR, exist_ok=True)

# --- Logging Setup ---
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Global State for Scheduler ---
scheduler = BackgroundScheduler()
all_cpanel_users = [] # List of all cPanel usernames to monitor
current_batch_index = 0 # Tracks which batch is currently being processed
last_full_cycle_start_time = None # Timestamp of when the current full cycle started
collection_lock = threading.Lock() # To prevent concurrent runs of the collection job

# --- Authentication Decorator ---
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not API_KEY: # Should not happen if install script ran correctly
            logger.error("API Key is not configured on the server agent.")
            return jsonify({"error": "Server configuration error: API Key not set."}), 500

        provided_key = request.headers.get('X-API-KEY')
        if not provided_key or provided_key != API_KEY:
            logger.warning(f"Unauthorized API access attempt. Provided key: '{provided_key}'")
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

# --- Helper for running commands ---
def run_command(command_parts):
    """
    Runs a command using subprocess and returns success, stdout, stderr.
    Command_parts should be a list of arguments (e.g., ['sudo', 'lvectl', ...])
    """
    try:
        logger.info(f"Executing command: {' '.join(command_parts)}")
        process = subprocess.run(command_parts, capture_output=True, text=True, check=False)

        if process.returncode == 0:
            logger.info(f"Command successful. STDOUT: {process.stdout.strip()}")
            return True, process.stdout.strip(), process.stderr.strip()
        else:
            logger.error(f"Command failed. Return code: {process.returncode}. STDERR: {process.stderr.strip()}. STDOUT: {process.stdout.strip()}")
            return False, process.stdout.strip(), process.stderr.strip()
    except FileNotFoundError:
        logger.error(f"Command not found: {command_parts[0]}")
        return False, "", f"Command not found: {command_parts[0]}"
    except Exception as e:
        logger.exception(f"Exception during command execution: {e}")
        return False, "", str(e)

# --- LVE Usage Collection Functions ---

def get_all_cpanel_users_from_django():
    """
    Fetches the list of all active cPanel usernames from the Django backend.
    Assumes a Django API endpoint like /api/users/cpanel-usernames/ that returns
    a JSON list of strings (e.g., ["user1", "user2", "user3"]).
    """
    global all_cpanel_users
    try:
        url = f"{DJANGO_API_BASE_URL}users/cpanel-usernames/"
        headers = {'X-API-KEY': DJANGO_API_KEY_FOR_FLASK}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        users = response.json() # Expected to be a direct list, not {'cpanel_usernames': [...]}
        if isinstance(users, list) and all(isinstance(u, str) for u in users):
            all_cpanel_users = users
            logger.info(f"Successfully fetched {len(all_cpanel_users)} cPanel users from Django.")
        else:
            logger.error(f"Django API returned unexpected format for cPanel usernames: {users}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to fetch cPanel users from Django: {e}")
        # Fallback to a predefined list or empty list if Django is unreachable
        if not all_cpanel_users: # Only use fallback if list is currently empty
            all_cpanel_users = ["mockuser1", "mockuser2", "mockuser3", "mockuser4", "mockuser5", "mockuser6", "mockuser7", "mockuser8"]
            logger.warning("Using mock cPanel users as fallback due to Django API error.")
    except Exception as e:
        logger.exception(f"An unexpected error occurred while fetching cPanel users: {e}")
        if not all_cpanel_users:
             all_cpanel_users = ["mockuser1", "mockuser2", "mockuser3", "mockuser4", "mockuser5", "mockuser6", "mockuser7", "mockuser8"]
             logger.warning("Using mock cPanel users as fallback due to unexpected error.")


def parse_lvetop_output(output, username):
    """
    Parses lvetop output for a specific user's CPU, RAM, IO, IOPS, EP, NPROC usage.
    This version attempts to find column headers for more robust parsing.
    """
    lines = output.splitlines()
    
    if not lines:
        logger.warning("lvetop output is empty.")
        return 0, 0, 0, 0, 0, 0 # CPU, RAM, IO, IOPS, EP, NPROC

    # Identify header line (usually the first non-empty line with many words)
    header_line = None
    for line in lines:
        if len(line.strip().split()) > 5: # Assume header has at least 6 columns
            header_line = line.strip()
            break
    
    if not header_line:
        logger.warning("Could not identify header line in lvetop output. Falling back to simple parsing.")
        # If header not found, fall back to fixed indices (less robust)
        return _parse_lvetop_output_fixed_indices(output, username)

    headers = header_line.split()
    
    # Find the data line for the specific username
    data_line = None
    for line in lines:
        # Check if the line starts with the username or contains it as a distinct word
        if line.strip().startswith(username + ' ') or (' ' + username + ' ' in line and line.strip().split()[0] != username):
            data_line = line.strip()
            break
    
    if not data_line:
        logger.warning(f"User '{username}' not found in lvetop output. Returning 0 usage for all metrics.")
        return 0, 0, 0, 0, 0, 0

    parts = data_line.split()
    
    # Map header names to their column index
    header_map = {h: i for i, h in enumerate(headers)}

    # Initialize usage values
    cpu_usage = 0.0
    ram_usage = 0.0 # Will be converted to percentage
    io_usage = 0.0
    iops_usage = 0.0
    ep_usage = 0
    nproc_usage = 0

    try:
        # CPU usage (usually 'CPU%' or 'CPU')
        if 'CPU%' in header_map:
            cpu_usage = float(parts[header_map['CPU%']].strip('%'))
        elif 'CPU' in header_map:
            cpu_usage = float(parts[header_map['CPU']])

        # RAM usage (usually 'MEM' or 'PMEM' in MB/GB)
        # We need to convert this to a percentage based on allocated limits.
        # For simplicity, we'll assume a default 1GB (1024MB) limit for percentage conversion.
        # A more accurate solution would fetch the actual limit from Django model.
        default_ram_limit_mb = 1024.0 # Example: Assume 1GB default RAM limit for % calculation
        mem_val_mb = 0.0
        if 'MEM' in header_map:
            mem_str = parts[header_map['MEM']]
            mem_val_mb = float(mem_str.strip('M')) if mem_str.endswith('M') else float(mem_str)
        elif 'PMEM' in header_map: # Physical Memory
            mem_str = parts[header_map['PMEM']]
            mem_val_mb = float(mem_str.strip('M')) if mem_str.endswith('M') else float(mem_str)
        
        if mem_val_mb > 0 and default_ram_limit_mb > 0:
            ram_usage = (mem_val_mb / default_ram_limit_mb) * 100
            ram_usage = min(100.0, max(0.0, ram_usage)) # Cap at 100%

        # I/O Throughput (usually 'IO')
        if 'IO' in header_map:
            io_str = parts[header_map['IO']]
            io_usage = float(io_str.strip('K')) if io_str.endswith('K') else float(io_str)
        
        # IOPS
        if 'IOPS' in header_map:
            iops_usage = float(parts[header_map['IOPS']])

        # Entry Processes (EP)
        if 'EP' in header_map:
            ep_usage = int(parts[header_map['EP']])
        
        # Number of Processes (NPROC)
        if 'NPROC' in header_map:
            nproc_usage = int(parts[header_map['NPROC']])

        logger.info(f"Parsed usage for {username}: CPU={cpu_usage}%, RAM={ram_usage}%, IO={io_usage}KB/s, IOPS={iops_usage}, EP={ep_usage}, NPROC={nproc_usage}")
        return cpu_usage, ram_usage, io_usage, iops_usage, ep_usage, nproc_usage

    except (ValueError, IndexError) as e:
        logger.error(f"Error parsing lvetop output for {username} using headers: {e}. Data line: '{data_line}'. Headers: {headers}. Returning 0 usage for all metrics.")
        return 0, 0, 0, 0, 0, 0

def _parse_lvetop_output_fixed_indices(output, username):
    """
    Fallback parsing for lvetop output using fixed indices. Less robust.
    Used if header parsing fails.
    """
    lines = output.splitlines()
    for line in lines:
        if username in line:
            parts = line.strip().split()
            try:
                # These indices are highly speculative and depend on actual lvetop output
                # Example lvetop output: ID EP PNO TNO CPU MEM IO IOPS
                # If this is the format, indices might be: CPU=4, MEM=5, IO=6, IOPS=7, EP=1, NPROC=2
                cpu_usage = float(parts[4].strip('%')) if parts[4].endswith('%') else float(parts[4])
                mem_str = parts[5]
                mem_val_mb = float(mem_str.strip('M')) if mem_str.endswith('M') else float(mem_str)
                default_ram_limit_mb = 1024.0 # Same assumption as above
                ram_usage = (mem_val_mb / default_ram_limit_mb) * 100
                ram_usage = min(100.0, max(0.0, ram_usage))

                io_usage = float(parts[6].strip('K')) if parts[6].endswith('K') else float(parts[6])
                iops_usage = float(parts[7])
                ep_usage = int(parts[1])
                nproc_usage = int(parts[2]) # PNO is often nproc count

                logger.warning(f"Parsed usage for {username} using fixed indices (fallback).")
                return cpu_usage, ram_usage, io_usage, iops_usage, ep_usage, nproc_usage
            except (ValueError, IndexError) as e:
                logger.error(f"Fixed-index parsing also failed for {username}: {e}. Line: '{line}'. Returning 0 usage.")
                return 0, 0, 0, 0, 0, 0
    logger.warning(f"User '{username}' not found in lvetop output for fixed-index parsing.")
    return 0, 0, 0, 0, 0, 0


def fetch_lve_usage_for_users(users_in_batch):
    """
    Fetches LVE usage for a given list of users using lvetop.
    Returns a list of dictionaries with usage data.
    """
    collected_data = []
    
    # Run lvetop without any problematic flags
    success, stdout, stderr = run_command(['sudo', '/usr/sbin/lvetop']) 
    
    if not success:
        logger.error(f"Failed to get lvetop output: {stderr}. Cannot collect usage for batch.")
        # Return empty data or mock data for this batch
        for user in users_in_batch:
            collected_data.append({
                "cpanel_username": user,
                "cpu_usage": 0, # Fallback
                "ram_usage": 0, # Fallback
                "io_usage": 0,
                "iops_usage": 0,
                "ep_usage": 0,
                "nproc_usage": 0,
                "timestamp": datetime.now().isoformat()
            })
        return collected_data

    for user in users_in_batch:
        cpu_usage, ram_usage, io_usage, iops_usage, ep_usage, nproc_usage = parse_lvetop_output(stdout, user)
        collected_data.append({
            "cpanel_username": user,
            "cpu_usage": cpu_usage,
            "ram_usage": ram_usage,
            "io_usage": io_usage,
            "iops_usage": iops_usage,
            "ep_usage": ep_usage,
            "nproc_usage": nproc_usage,
            "timestamp": datetime.now().isoformat()
        })
    return collected_data

def save_usage_to_file(data):
    """Saves collected usage data to a timestamped JSON file."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(LVE_DATA_DIR, f'lve_usage_{timestamp}.json')
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        logger.info(f"Saved LVE usage data to {filename}")
        return True
    except IOError as e:
        logger.error(f"Failed to save LVE usage data to file {filename}: {e}")
        return False

def delete_old_usage_files():
    """Deletes LVE usage files older than LVE_FILE_LIFETIME_MINUTES."""
    cutoff_time = datetime.now() - timedelta(minutes=LVE_FILE_LIFETIME_MINUTES)
    for filename in glob.glob(os.path.join(LVE_DATA_DIR, 'lve_usage_*.json')):
        try:
            file_timestamp_str = os.path.basename(filename).replace('lve_usage_', '').replace('.json', '')
            # Try parsing with microsecond if present, otherwise without
            try:
                file_time = datetime.strptime(file_timestamp_str, '%Y%m%d_%H%M%S.%f')
            except ValueError:
                file_time = datetime.strptime(file_timestamp_str, '%Y%m%d_%H%M%S')
            
            if file_time < cutoff_time:
                os.remove(filename)
                logger.info(f"Deleted old LVE usage file: {filename}")
        except Exception as e:
            logger.error(f"Error deleting file {filename}: {e}")

def send_usage_to_django(data):
    """Sends collected LVE usage data to the Django backend API."""
    if not DJANGO_API_KEY_FOR_FLASK:
        logger.error("DJANGO_API_KEY_FOR_FLASK is not set. Cannot send data to Django.")
        return False

    if not data:
        logger.info("No usage data to send to Django.")
        return True # Considered successful if nothing to send

    try:
        url = f"{DJANGO_API_BASE_URL}lve-usage/store/" # Assuming this endpoint exists in Django
        headers = {
            'Content-Type': 'application/json',
            'X-API-KEY': DJANGO_API_KEY_FOR_FLASK # Django API key for this Flask agent
        }
        response = requests.post(url, json=data, headers=headers, timeout=30)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        logger.info(f"Successfully sent {len(data)} usage records to Django. Response: {response.status_code}")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send LVE usage data to Django: {e}")
        return False
    except Exception as e:
        logger.exception(f"An unexpected error occurred while sending data to Django: {e}")
        return False

# --- Scheduled Job ---
def collect_lve_data_batch():
    """
    The main scheduled job. Collects LVE data for a batch of users,
    saves it to file, and sends it to Django.
    """
    with collection_lock: # Ensure only one instance of this job runs at a time
        global all_cpanel_users, current_batch_index, last_full_cycle_start_time

        if not all_cpanel_users:
            logger.info("No cPanel users available for LVE collection. Attempting to fetch from Django.")
            get_all_cpanel_users_from_django()
            if not all_cpanel_users:
                logger.warning("Still no cPanel users after fetch attempt. Skipping collection.")
                return

        # Calculate batch size
        num_users = len(all_cpanel_users)
        if num_users == 0:
            logger.info("No users to process in all_cpanel_users list. Skipping batch.")
            return
            
        batch_size = (num_users + LVE_BATCH_DIVISOR - 1) // LVE_BATCH_DIVISOR # Ceil division
        
        start_index = current_batch_index * batch_size
        end_index = min(start_index + batch_size, num_users)
        
        users_in_batch = all_cpanel_users[start_index:end_index]
        
        if not users_in_batch:
            logger.info("Current batch is empty. This might happen if user list changed or batching logic misfired.")
            return

        logger.info(f"Processing batch {current_batch_index + 1}/{LVE_BATCH_DIVISOR} for {len(users_in_batch)} users.")
        
        # 1. Fetch LVE usage for the current batch
        collected_usage_data = fetch_lve_usage_for_users(users_in_batch)
        
        # 2. Save usage to a temporary file
        if collected_usage_data:
            save_usage_to_file(collected_usage_data)
        
        # 3. Send usage data to Django
        if collected_usage_data:
            send_usage_to_django(collected_usage_data)
        
        # Increment batch index
        current_batch_index += 1
        
        # Check if all batches in a cycle are complete
        if current_batch_index >= LVE_BATCH_DIVISOR:
            logger.info(f"Completed a full cycle of LVE collection. Cycle started at {last_full_cycle_start_time}")
            current_batch_index = 0 # Reset for the next cycle
            last_full_cycle_start_time = datetime.now() # Mark start of new cycle
            # 4. Delete old files after a full cycle and sufficient time has passed
            delete_old_usage_files()
            # Also, refresh the user list for the next cycle to catch new/deleted users
            get_all_cpanel_users_from_django()


# --- API Endpoints (from original script) ---
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy", "message": "cPanel Agent is running"}), 200

@app.route('/api/lve/set-user-limits', methods=['POST'])
@require_api_key # Protect this endpoint
def set_lve_user_limits():
    logger.info(f"Received request on /api/lve/set-user-limits from {request.remote_addr}")
    data = request.json
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    cpanel_user = data.get('cpanel_user')
    limits = data.get('limits') # Expected to be a dictionary: {"speed": "100%", "pmem": "1024M", ...}

    if not cpanel_user or not isinstance(cpanel_user, str) or not cpanel_user.isalnum(): # Basic validation
        logger.warning(f"Invalid or missing cpanel_user: {cpanel_user}")
        return jsonify({"error": "Invalid or missing 'cpanel_user'"}), 400
    if not limits or not isinstance(limits, dict):
        logger.warning(f"Invalid or missing 'limits' dictionary: {limits}")
        return jsonify({"error": "Invalid or missing 'limits' dictionary"}), 400

    cmd = ['sudo', '/usr/sbin/lvectl', 'set-user', cpanel_user]

    allowed_lve_params_map = {
        'speed': {'arg': '--speed', 'unit': '%'},
        'pmem':  {'arg': '--pmem',  'unit': 'M'},
        'vmem':  {'arg': '--vmem',  'unit': 'M'},
        'io':    {'arg': '--io',    'unit': 'K'},
        'iops':  {'arg': '--iops',  'unit': ''},
        'nproc': {'arg': '--nproc', 'unit': ''},
        'ep':    {'arg': '--entry-processes', 'unit': ''}
    }

    has_valid_limits = False
    for key, value in limits.items(): # Changed value_str to value
        if key in allowed_lve_params_map:
            spec = allowed_lve_params_map[key]
            try:
                # Handle "DEFAULT" explicitly
                if str(value).upper() == "DEFAULT":
                    cmd.append(f"{spec['arg']}=DEFAULT")
                    has_valid_limits = True
                elif spec['unit'] and not str(value).endswith(spec['unit']):
                    # If unit is expected and not present, try to parse as number and append unit.
                    num_val = float(value) # Use float for more flexibility with numbers
                    # Specific handling for speed for percentage if value is like 100 (not "100%")
                    if key == 'speed' and not str(value).endswith('%'):
                        cmd.append(f"{spec['arg']}={int(num_val)}{spec['unit']}") # Convert to int for %
                    else:
                        cmd.append(f"{spec['arg']}={num_val}{spec['unit']}")
                    has_valid_limits = True
                else: # Value might already have unit or no unit needed
                    cmd.append(f"{spec['arg']}={shlex.quote(str(value))}") # Quote for safety
                    has_valid_limits = True
            except ValueError:
                logger.warning(f"Invalid numeric value for LVE limit {key}: {value}")
                return jsonify({"error": f"Invalid value for limit '{key}': must be a number or 'DEFAULT'"}), 400
        else:
            logger.warning(f"Unknown LVE limit parameter received: {key}")

    if not has_valid_limits and len(cmd) == 4:
        logger.info(f"No specific limits provided for {cpanel_user}. Will attempt to reset to package defaults.")
    elif not has_valid_limits:
        return jsonify({"error": "No valid LVE limits provided"}), 400

    success, stdout, stderr = run_command(cmd)

    if success:
        return jsonify({"message": "LVE limits updated successfully", "user": cpanel_user, "details": stdout or "OK"}), 200
    else:
        return jsonify({"error": "Failed to update LVE limits", "details": stderr or stdout or "Unknown error"}), 500

if __name__ == '__main__':
    # Initialize the list of users once at startup
    get_all_cpanel_users_from_django()
    
    # Start the scheduler
    # The 'interval' trigger runs the job every N seconds.
    scheduler.add_job(
        func=collect_lve_data_batch,
        trigger='interval',
        seconds=LVE_COLLECTION_INTERVAL_SECONDS,
        id='lve_usage_collection_job',
        name='LVE Usage Collection Batch Job'
    )
    scheduler.start()

    # Shut down the scheduler when the app exits
    atexit.register(lambda: scheduler.shutdown())

    logger.info(f"Starting cPanel Agent Flask API on {FLASK_HOST}:{FLASK_PORT}")
    # For production, use Gunicorn via systemd as configured in the bash script
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=(os.getenv('FLASK_DEBUG', 'False').lower() == 'true'))


    cat << EOF > "$SERVICE_FILE"
[Unit]
Description=cPanel Agent Flask API
After=network.target

[Service]
User=$API_USER
Group=$API_USER # Or the primary group of $API_USER
WorkingDirectory=$APP_DIR
# Load environment variables from .env file
EnvironmentFile=-$APP_DIR/.env 
ExecStart=$VENV_DIR/bin/gunicorn --workers 2 --bind \${FLASK_HOST}:\${FLASK_PORT} wsgi:app
Restart=always
StandardOutput=append:$LOG_FILE
StandardError=append:$LOG_FILE

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable cpanel_agent.service
    systemctl start cpanel_agent.service
    log_message "Systemd service 'cpanel_agent.service' created, enabled, and started."
    log_message "Agent API Key (for Django to use): $API_SECRET_KEY"
    log_message "Please store this API key securely in your Django application's settings."
}

# --- Main Script Execution ---
check_root
detect_os_and_install_python
create_api_user
setup_ssh_key # Optional for direct SSH access to API_USER, not for Flask API auth
configure_sudo
setup_flask_app
setup_systemd_service # This will also generate and display the API Key

log_message "-----------------------------------------------------"
log_message "cPanel Agent Installation Complete!"
log_message "API User: $API_USER"
log_message "Application Directory: $APP_DIR"
log_message "Flask API should be listening on http://localhost:$FLASK_APP_PORT"
log_message "Service status: systemctl status cpanel_agent.service"
log_message "Logs: $LOG_FILE and journalctl -u cpanel_agent.service"
log_message "Remember to configure your Django application to use the generated API Key for authentication."
log_message "-----------------------------------------------------"

exit 0
