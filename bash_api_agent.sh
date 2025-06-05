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
from dotenv import load_dotenv

load_dotenv() # Loads variables from .env

app = Flask(__name__)

# Configure logging
logging.basicConfig(filename=os.getenv('LOG_FILE', 'agent.log'), level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s')

# Simple health check
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"}), 200

# TODO: Add authentication for API endpoints (e.g., API key)
# TODO: Add LVE set-user endpoint

if __name__ == '__main__':
    app.run(host=os.getenv('FLASK_HOST', '127.0.0.1'), 
            port=int(os.getenv('FLASK_PORT', 5858)), 
            debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true')
EOF

    # .env file for configuration
    cat << EOF > "$APP_DIR/.env"
FLASK_APP=app.py
FLASK_ENV=production # or development
FLASK_DEBUG=False
FLASK_HOST=127.0.0.1
FLASK_PORT=$FLASK_APP_PORT
LOG_FILE=$LOG_FILE
# Add API_KEY here if you implement token authentication
# API_KEY=your_generated_secret_token_here
EOF

    # wsgi.py for Gunicorn
    cat << EOF > "$APP_DIR/wsgi.py"
from app import app

if __name__ == "__main__":
    app.run()
EOF
    chown -R "$API_USER:$API_USER" "$APP_DIR"
    chmod -R 750 "$APP_DIR" # User rwx, group rx, other ---
    chmod 640 "$APP_DIR/.env" # Restrict .env file access

    log_message "Flask app structure created. Main app file: $APP_DIR/app.py"
}

setup_systemd_service() {
    log_message "Setting up systemd service for the Flask agent..."
    # Generate a secret key for API authentication if not set
    API_SECRET_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32 ; echo '')
    # Append to .env (or update if exists)
    if grep -q "API_KEY=" "$APP_DIR/.env"; then
        sed -i "s/^API_KEY=.*/API_KEY=$API_SECRET_KEY/" "$APP_DIR/.env"
    else
        echo "API_KEY=$API_SECRET_KEY" >> "$APP_DIR/.env"
    fi
    chown "$API_USER:$API_USER" "$APP_DIR/.env"
    chmod 600 "$APP_DIR/.env" # Ensure .env is private

    SERVICE_FILE="/etc/systemd/system/cpanel_agent.service"
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
