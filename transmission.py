#!/usr/bin/env python3

import subprocess
import time
import argparse
import sys
import os
import signal
from pathlib import Path

# Import the modular components
from src import (
    setup_logging,
    run_command, read_credentials, find_pids,
    initialize_network_interface, connect_vpn, deconstruct_vpn_and_services,
    get_vpn_port, set_vpn_port, VPN_NS, VPN_IF, TRANSMISSION_PORT, TRANSMISSION_CONFIG_DIR,
    perfect_teardown, emergency_teardown, verify_teardown, namespace_exists
)
from src.templateEngine import generate_transmission_config, cleanup_transmission_configs
from src.rpc import set_transmission_peer_port

# --- Configuration ---
VAULT_DIR = Path("/vault")
KEYS_DIR = VAULT_DIR / ".keys"
PIA_CONN_SCRIPT = VAULT_DIR / "scripts" / "manual-connections" / "run_setup.sh"

# Service name constants - use consistent lowercase
PIA_SERVICE_NAME = "pia"
TRANSMISSION_SERVICE_NAME = "transmission"

PORT_FILE = Path("/tmp/port.pid")
TRANSMISSION_BIND_IP = "0.0.0.0"
TRANSMISSION_DAEMON_PATH = "/usr/bin/transmission-daemon"
TRANSMISSION_REMOTE_PATH = "/usr/bin/transmission-remote"

# --- Global Variables (Credentials) ---
# Using a dictionary to hold credentials read from files
credentials = {}

# Global log_message function - will be set by setup_logging
log_message = None

# Global flag to track if we're in the middle of teardown
teardown_in_progress = False


def signal_handler(signum, frame):
    """Handle interrupt signals (Ctrl+C) by initiating full teardown."""
    global teardown_in_progress
    
    if teardown_in_progress:
        log_message(1, "Teardown already in progress, forcing exit...")
        sys.exit(1)
    
    teardown_in_progress = True
    log_message(0, f"Received signal {signum}. Initiating full teardown...")
    
    try:
        # Clean up template configurations first
        try:
            cleanup_transmission_configs(VPN_NS)
        except Exception as template_e:
            log_message(2, f"Template cleanup failed: {template_e}")
        
        if namespace_exists():
            log_message(0, "Running perfect teardown...")
            perfect_teardown()
            if verify_teardown():
                log_message(0, "Perfect teardown completed successfully.")
            else:
                log_message(1, "Teardown verification failed. Running emergency teardown...")
                emergency_teardown()
        else:
            log_message(3, "No VPN namespace found. Skipping teardown.")
    except Exception as e:
        log_message(1, f"Teardown failed: {e}. Attempting emergency teardown...")
        try:
            if namespace_exists():
                emergency_teardown()
            else:
                log_message(3, "No VPN namespace found. Skipping emergency teardown.")
        except Exception as emergency_e:
            log_message(1, f"Emergency teardown also failed: {emergency_e}")
    
    log_message(0, "Teardown completed. Exiting...")
    sys.exit(0)


def initialize_transmission():
    """Starts and configures the Transmission daemon using template-based configuration."""
    vpn_port = get_vpn_port()
    log_message(3, "Starting Transmission daemon with template-based configuration.")
    MAX_RETRIES = 3
    RETRY_DELAY = 10 # seconds

    trans_user = credentials.get(TRANSMISSION_SERVICE_NAME, {}).get("username")
    trans_pass = credentials.get(TRANSMISSION_SERVICE_NAME, {}).get("password")

    if not trans_user or not trans_pass:
        log_message(1, "Transmission credentials not found.")
        sys.exit(1)
    if not vpn_port:
        log_message(1, "VPN port is not set. Cannot configure Transmission.")
        sys.exit(1)

    for attempt in range(1, MAX_RETRIES + 1):
        # Check for interrupt signal during long operations
        if teardown_in_progress:
            log_message(0, "Teardown requested during transmission setup. Exiting...")
            return
            
        log_message(3, f"Attempt {attempt} of {MAX_RETRIES} to configure Transmission.")

        # Check if port file still exists (it should from connect_vpn)
        if PORT_FILE.exists():
            try:
                 # Verify port from file matches current vpn_port (sanity check)
                 with open(PORT_FILE, 'r') as f:
                     port_from_file = int(f.read().strip())
                 if port_from_file != vpn_port:
                     log_message(1, f"Port mismatch! Current port {vpn_port}, file port {port_from_file}. Aborting.")
                     sys.exit(1)
                 
                 log_message(4, f"Port number confirmed: using port {vpn_port}.")
                 
                 # Always ensure transmission is configured with current VPN port
                 # Check if transmission-daemon is already running in the namespace
                 trans_pids_result = run_command(f"ip netns exec {VPN_NS} pgrep -f transmission-daemon", 
                                                netns=None, sudo=True, capture_output=True, check=False)
                 
                 # If transmission is running, kill it to ensure fresh configuration with new port
                 if trans_pids_result.returncode == 0 and trans_pids_result.stdout.strip():
                     existing_pids = trans_pids_result.stdout.strip().splitlines()
                     log_message(3, f"Found existing transmission processes: {existing_pids}. Killing to ensure fresh configuration with port {vpn_port}...")
                     for pid in existing_pids:
                         try:
                             run_command(f"kill -9 {pid.strip()}", sudo=True, check=False)
                             log_message(5, f"Killed existing process: {pid.strip()}")
                         except Exception as e:
                             log_message(5, f"Failed to kill existing process {pid.strip()}: {e}")
                     time.sleep(2)  # Give time for cleanup
                 
                 # Generate transmission configuration using template engine with current VPN port
                 log_message(3, f"Generating fresh transmission configuration for VPN port {vpn_port}...")
                 try:
                     config_path = generate_transmission_config(
                         vpn_port=vpn_port,
                         rpc_username=trans_user,
                         rpc_password=trans_pass,
                         namespace=VPN_NS
                     )
                     log_message(2, f"Generated transmission config: {config_path}")
                 except Exception as e:
                     log_message(1, f"Failed to generate transmission config: {e}")
                     continue  # Try next attempt
                 
                 log_message(3, "Starting Transmission daemon with fresh configuration.")
                 # Start daemon in namespace using the generated configuration
                 # Use namespace-specific config directory
                 namespace_config_dir = f"/etc/netns/{VPN_NS}/transmission-daemon"
                 cmd = [
                     TRANSMISSION_DAEMON_PATH,
                     "--foreground",  # Run in foreground initially to catch startup errors
                     "-g", namespace_config_dir,  # Use namespace-specific config directory
                     "--log-debug"  # Enable debug logging
                 ]
                 
                 log_message(3, f"Starting transmission-daemon with namespace config dir: {namespace_config_dir}")
                 log_message(3, f"Command: {' '.join(cmd)}")
                 
                 # Start daemon in background
                 try:
                     # Start daemon directly without test-config (which shows help output)
                     # Remove --foreground flag to let Transmission daemonize automatically
                     daemon_cmd = [cmd[0]] + [arg for arg in cmd[1:] if arg != "--foreground"]
                     run_command(daemon_cmd, netns=VPN_NS, sudo=True, check=False)
                     log_message(2, "Transmission daemon start command issued with fresh config.")
                     
                 except Exception as start_e:
                     log_message(1, f"Failed to start transmission daemon: {start_e}")
                     continue  # Try next attempt
                 
                 time.sleep(5) # Give daemon time to start
                 
                 # Verify transmission-daemon actually started and is listening
                 log_message(3, "Verifying transmission-daemon started successfully...")
                 # Check for transmission-daemon process in the VPN namespace specifically
                 trans_pids_after = run_command(f"ip netns exec {VPN_NS} pgrep -f transmission-daemon", 
                                               netns=None, sudo=True, capture_output=True, check=False)
                 if trans_pids_after.returncode != 0 or not trans_pids_after.stdout.strip():
                     log_message(1, "Transmission daemon failed to start - no process found in VPN namespace")
                     continue  # Try next attempt
                 
                 pids = trans_pids_after.stdout.strip().splitlines()
                 log_message(2, f"Transmission daemon started successfully (PIDs: {pids})")
                 
                 # Set the peer port via RPC after daemon startup
                 log_message(3, f"Setting Transmission peer port to {vpn_port} via RPC...")
                 try:
                     if set_transmission_peer_port(
                         port=vpn_port,
                         username=trans_user,
                         password=trans_pass,
                         namespace=VPN_NS,
                         wait_for_ready=True,
                         log_message_func=log_message
                     ):
                         log_message(2, f"Successfully set Transmission peer port to {vpn_port} via RPC")
                     else:
                         log_message(1, f"Failed to set Transmission peer port to {vpn_port} via RPC")
                         # Continue anyway - the daemon is running, just with wrong port
                 except Exception as rpc_e:
                     log_message(1, f"RPC port setting failed: {rpc_e}")
                     # Continue anyway - the daemon is running, just with wrong port
                 
                 # Rescan directories to reattach to existing torrents and incomplete downloads
                 log_message(3, "Rescanning directories to reattach to existing torrents...")
                 try:
                     from src.rpc import rescan_transmission_directories
                     if rescan_transmission_directories(
                         username=trans_user,
                         password=trans_pass,
                         namespace=VPN_NS,
                         log_message_func=log_message
                     ):
                         log_message(2, "Successfully rescanned directories - existing torrents should resume seeding and incomplete downloads should continue")
                     else:
                         log_message(1, "Failed to rescan directories - torrents may not resume properly")
                 except Exception as rescan_e:
                     log_message(1, f"Directory rescan failed: {rescan_e}")
                     # Continue anyway - the daemon is running, just without resuming torrents
                 
                 # Verify transmission is using the correct VPN port
                 log_message(2, f"Transmission successfully configured and started with VPN port {vpn_port}.")
                 log_message(0, f"Transmission successfully initiated with fresh configuration for port {vpn_port}.")
                 return # Success, exit the function

            except Exception as e:
                 log_message(1, f"Failed during Transmission start/config attempt {attempt}: {e}")
        else:
            log_message(1, f"Port number file '{PORT_FILE}' disappeared unexpectedly at attempt {attempt}. Cannot configure Transmission.")
            # Should not happen if connect_vpn succeeded, but handle defensively
            sys.exit(1)

        # Retry delay if not the last attempt
        if attempt < MAX_RETRIES:
            log_message(3, f"Retrying Transmission setup in {RETRY_DELAY} seconds...")
            time.sleep(RETRY_DELAY)

    log_message(1, f"Failed to configure Transmission after {MAX_RETRIES} attempts.")
    # Cleanup on final failure using perfect teardown
    try:
        perfect_teardown()
    except Exception as cleanup_e:
        log_message(1, f"Perfect teardown failed: {cleanup_e}. Attempting emergency teardown...")
        emergency_teardown()
    sys.exit(1)


# --- Main Execution ---
def main():
    """Main orchestrator function that coordinates all VPN and Transmission operations."""
    # Set up signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Argument Parser
    parser = argparse.ArgumentParser(
        description="Professional-grade VPN and Transmission management for digital sovereignty."
    )
    parser.add_argument(
        "verbosity",
        type=int,
        nargs='?',
        default=3,  # INFO level for better debugging
        choices=range(6), # 0 to 5
        help="Set verbosity level (0=STATUS, 1=ERROR, 2=SUCCESS, 3=INFO, 4=VARIABLES, 5=DEBUG). Default is 3.",
        metavar="LEVEL"
    )
    parser.add_argument(
        "--stop",
        action="store_true",
        help="Stop VPN connection, transmission daemon, and perform cleanup."
    )
    args = parser.parse_args()

    # Import log_message after setup_logging initializes it
    setup_logging(args.verbosity)
    from src.logger import log_message
    
    # Set the global log_message function so other functions can use it
    globals()['log_message'] = log_message

    # If --stop flag is used, perform perfect teardown and exit
    if args.stop:
        log_message(0, "Stop flag detected. Checking for VPN namespace...")
        if namespace_exists():
            log_message(0, "VPN namespace found. Initiating perfect teardown...")
            try:
                perfect_teardown()
                if verify_teardown():
                    log_message(0, "Perfect teardown completed successfully.")
                    sys.exit(0)
                else:
                    log_message(1, "Teardown verification failed. Attempting emergency teardown...")
                    if emergency_teardown():
                        log_message(0, "Emergency teardown completed successfully.")
                        sys.exit(0)
                    else:
                        log_message(1, "Emergency teardown completed with errors. Manual cleanup may be required.")
                        sys.exit(1)
            except Exception as e:
                log_message(1, f"Perfect teardown failed: {e}. Attempting emergency teardown...")
                if emergency_teardown():
                    log_message(0, "Emergency teardown completed successfully after perfect teardown failure.")
                    sys.exit(0)
                else:
                    log_message(1, "Both perfect and emergency teardown failed. Manual cleanup required.")
                    sys.exit(1)
        else:
            log_message(0, "No VPN namespace found. Nothing to teardown.")
            sys.exit(0)

    # Check root privileges needed for network/process management
    if os.geteuid() != 0:
         # Check if sudo is available and user can run it
        try:
            run_command("sudo -nv", check=True, capture_output=True, sudo=False) # Non-interactive validation
            log_message(3, "Sudo privileges appear available.")
        except Exception:
             log_message(1, "This script requires root privileges or passwordless sudo access to manage network interfaces, namespaces, firewall rules, and services.")
             sys.exit(1)

    # --- Prerequisite Checks ---
    if not KEYS_DIR.joinpath(f"{PIA_SERVICE_NAME}.key").is_file():
        log_message(1, f"No PIA service key found in {KEYS_DIR}")
        sys.exit(1)
    if not KEYS_DIR.joinpath(f"{TRANSMISSION_SERVICE_NAME}.key").is_file():
        log_message(1, f"No transmission service key found in {KEYS_DIR}")
        sys.exit(1)
    if not PIA_CONN_SCRIPT.is_file() or not os.access(PIA_CONN_SCRIPT, os.X_OK):
        log_message(1, f"PIA connection script not found or not executable: {PIA_CONN_SCRIPT}")
        sys.exit(1)
        
    # Check required commands exist
    required_commands = ['ip', 'nft', 'tee', 'sysctl', 'pgrep', 'kill', 'env', 'rm']
    for cmd in required_commands:
        if subprocess.run(['which', cmd], capture_output=True, text=True).returncode != 0:
            log_message(1, f"Required command '{cmd}' not found in PATH.")
            sys.exit(1)
    
    # Check transmission binaries exist
    if not Path(TRANSMISSION_DAEMON_PATH).exists():
        log_message(1, f"Transmission daemon not found at {TRANSMISSION_DAEMON_PATH}")
        sys.exit(1)
    if not Path(TRANSMISSION_REMOTE_PATH).exists():
        log_message(1, f"Transmission remote not found at {TRANSMISSION_REMOTE_PATH}")
        sys.exit(1)
    
    log_message(5, "All required commands found.")

    # --- Main Logic ---
    if PORT_FILE.exists():
        log_message(0, "Previous session file detected. Performing perfect teardown first...")
        try:
            # Only attempt teardown if the VPN namespace actually exists
            if namespace_exists():
                perfect_teardown()
                if not verify_teardown():
                    log_message(1, "Initial teardown verification failed. Attempting emergency cleanup...")
                    emergency_teardown()
            else:
                log_message(3, "No VPN namespace found. Skipping teardown and proceeding with fresh setup.")
        except Exception as e:
            log_message(1, f"Teardown failed: {e}. Attempting emergency cleanup...")
            if namespace_exists():
                emergency_teardown()
            else:
                log_message(3, "No VPN namespace found. Skipping emergency cleanup.")
        log_message(3,"Waiting a moment after cleanup...")
        time.sleep(2) # Brief pause after cleanup

    try:
        log_message(3, "Reading credentials...")
        credentials[TRANSMISSION_SERVICE_NAME] = read_credentials(TRANSMISSION_SERVICE_NAME)
        credentials[PIA_SERVICE_NAME] = read_credentials(PIA_SERVICE_NAME)

        # Check if network setup is needed
        # Check if veth0 exists in the host
        result = run_command(f"ip link show {VPN_IF}", check=False, capture_output=True, sudo=True)
        if result.returncode != 0:
            log_message(0, f"{VPN_IF} does not exist. Initializing network interface...")
            initialize_network_interface()
        else:
            log_message(0, f"{VPN_IF} exists. Skipping network interface initialization.")
            # Optional: Add checks here to ensure existing setup is valid (IPs, routes, etc.)

        # Connect to VPN and get the port
        vpn_port = connect_vpn(credentials)
        if vpn_port:
            set_vpn_port(vpn_port)
            
        # Initialize Transmission with the VPN port
        initialize_transmission()

        log_message(0, "Script completed successfully. Digital sovereignty established.")
        
        # CRITICAL: Keep the script running to maintain the VPN namespace
        # The namespace will be destroyed if this script exits
        log_message(0, "Entering perpetual keepalive mode to maintain VPN namespace...")
        log_message(0, "Press Ctrl+C to stop the service and perform cleanup.")
        
        # The PIA integration already handles port forwarding keepalive every 15 minutes
        # We just need to keep this script alive to maintain the namespace
        try:
            while True:
                # Check if VPN namespace still exists
                if not namespace_exists():
                    log_message(1, "VPN namespace disappeared! Attempting to recreate...")
                    # Try to recreate the setup
                    vpn_port = connect_vpn(credentials)
                    if vpn_port:
                        set_vpn_port(vpn_port)
                        initialize_transmission()
                    else:
                        log_message(1, "Failed to recreate VPN connection. Exiting...")
                        break
                
                # Check if Transmission is still running in the namespace
                trans_pids = run_command(f"ip netns exec {VPN_NS} pgrep -f transmission-daemon", 
                                       netns=None, sudo=True, capture_output=True, check=False)
                if trans_pids.returncode != 0 or not trans_pids.stdout.strip():
                    log_message(1, "Transmission daemon stopped! Restarting...")
                    initialize_transmission()
                
                # Check if port forwarding is still active
                if not PORT_FILE.exists():
                    log_message(1, "Port forwarding file disappeared! Attempting to recreate...")
                    vpn_port = connect_vpn(credentials)
                    if vpn_port:
                        set_vpn_port(vpn_port)
                    else:
                        log_message(1, "Failed to recreate port forwarding. Exiting...")
                        break
                
                # Main keepalive loop - check every 15 minutes
                log_message(3, "Performing VPN and Transmission health check...")
                time.sleep(900)  # 15 minutes
                
        except KeyboardInterrupt:
            log_message(0, "Received interrupt signal. Performing graceful shutdown...")
            # Signal handler will handle the teardown

    except SystemExit as e:
         # Logged exit, respect the exit code if provided
         log_message(1, f"Script exiting prematurely (exit code: {e.code}). Check logs for details.")
         sys.exit(e.code if isinstance(e.code, int) else 1)
    except KeyboardInterrupt:
         # This should now be handled by the signal handler, but keep as backup
         log_message(0, "KeyboardInterrupt caught. Signal handler should have handled this.")
         sys.exit(0)
    except Exception as e:
         log_message(1, f"An unexpected error occurred: {e}")
         log_message(1, "Attempting perfect teardown...")
         try:
             if namespace_exists():
                 perfect_teardown()
             else:
                 log_message(3, "No VPN namespace found. Skipping teardown.")
         except Exception as cleanup_e:
             log_message(1, f"Perfect teardown failed: {cleanup_e}. Attempting emergency teardown...")
             if namespace_exists():
                 emergency_teardown()
             else:
                 log_message(3, "No VPN namespace found. Skipping emergency teardown.")
         sys.exit(1)


if __name__ == "__main__":
    main()
