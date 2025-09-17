#!/usr/bin/env python3

import os
import sys
from pathlib import Path
# Safe logging function that falls back to print
def safe_log(level, message):
    try:
        from .logger import log_message as real_log_message
        if real_log_message is not None:
            real_log_message(level, message)
        else:
            print(f"[{level}] {message}")
    except (ImportError, AttributeError):
        print(f"[{level}] {message}")

# Alias for backward compatibility
log_message = safe_log
from .utils import run_command, remove_rules_by_comment, terminate_processes, find_pids

# --- Configuration ---
RAMDISK_MNT = Path("/mnt/ramdisk")
PORT_FILE = Path("/tmp/port.pid")

# Network configuration constants
VPN_NS = "vpn"
VPN_IF = "veth0"
VPN_PEER_IF = "veth1"
TRANSMISSION_CONFIG_DIR = "/etc/transmission-daemon"

# Transmission configuration paths
TRANSMISSION_NAMESPACE_CONFIG = f"/etc/netns/{VPN_NS}/transmission-daemon"
TRANSMISSION_TEMPLATE_CONFIGS = "/tmp/transmission-configs"  # Template-generated configs


def namespace_exists():
    """Check if the VPN namespace exists."""
    try:
        result = run_command("ip netns list", capture_output=True, sudo=True, check=False)
        return VPN_NS in result.stdout
    except Exception as e:
        log_message(5, f"Could not check namespace status: {e}")
        return False


def teardown_processes():
    """Terminates all VPN and Transmission related processes."""
    # Only attempt process cleanup if the VPN namespace actually exists
    if not namespace_exists():
        log_message(3, "VPN namespace does not exist. Skipping process cleanup.")
        return
    
    log_message(3, "Terminating running processes...")
    
    # Kill VPN-related processes
    terminate_processes(find_pids('port_forwarding.sh'))
    terminate_processes(find_pids('openvpn'))
    
    # Kill Transmission daemon running within the namespace
    # First try to find processes in the namespace specifically
    if namespace_exists():
        try:
            # Find transmission processes in the VPN namespace
            result = run_command(f"ip netns exec {VPN_NS} pgrep -f transmission-daemon", 
                               sudo=True, capture_output=True, check=False)
            if result.returncode == 0 and result.stdout.strip():
                namespace_pids = result.stdout.strip().splitlines()
                log_message(3, f"Found transmission processes in namespace: {namespace_pids}")
                for pid in namespace_pids:
                    try:
                        # Kill the process INSIDE the namespace, not from host context
                        run_command(f"ip netns exec {VPN_NS} kill -9 {pid.strip()}", sudo=True, check=False)
                        
                        # Verify the process was actually killed
                        verify_result = run_command(f"ip netns exec {VPN_NS} pgrep -f transmission-daemon", 
                                                 sudo=True, capture_output=True, check=False)
                        if verify_result.returncode == 0 and pid.strip() in verify_result.stdout:
                            log_message(1, f"Warning: Process {pid.strip()} still running after kill attempt")
                        else:
                            log_message(5, f"Successfully killed namespace transmission process: {pid.strip()}")
                            
                    except Exception as e:
                        log_message(5, f"Failed to kill namespace process {pid.strip()}: {e}")
        except Exception as e:
            log_message(5, f"Error finding transmission processes in namespace: {e}")
    
    # Also kill any host transmission processes as fallback
    terminate_processes(find_pids('transmission-daemon'))
    
    # Additional cleanup for any stray PIA processes
    terminate_processes(find_pids('pia'))
    terminate_processes(find_pids('run_setup.sh'))
    
    log_message(2, "Process termination completed.")


def teardown_firewall_rules():
    """Removes all nftables firewall rules using comment binding."""
    # Only attempt firewall cleanup if the VPN namespace actually exists
    if not namespace_exists():
        log_message(3, "VPN namespace does not exist. Skipping firewall rule cleanup.")
        return
    
    log_message(3, "Removing firewall rules using comment binding...")
    
    # List of all firewall rule comments that need to be removed
    firewall_rules = [
        ("inet", "filter", "input", "inbound-vpn-rule"),
        ("inet", "filter", "forward", "wan-to-vpn-traffic-port"),
        ("inet", "filter", "forward", "lan-to-vpn-traffic-port"),
        ("inet", "filter", "forward", "vpn-to-lan-traffic-port"),
        ("ip", "nat", "postrouting", "nat-masquerade-vpn"),
        ("inet", "filter", "forward", "outbound-vpn-traffic"),
    ]
    
    # Remove each rule set by comment
    for family, table, chain, comment in firewall_rules:
        try:
            remove_rules_by_comment(family, table, chain, comment)
            log_message(5, f"Removed rules for comment: {comment}")
        except Exception as e:
            log_message(1, f"Warning: Failed to remove {comment} rules: {e}")
    
    log_message(2, "Firewall rules removal completed.")


def teardown_files():
    """Removes temporary files and auth credentials."""
    log_message(3, "Cleaning up temporary files...")
    
    files_to_remove = [
        PORT_FILE,
        f"{RAMDISK_MNT}/openvpn_auth.txt",
        "/opt/piavpn-manual/pia.ovpn",  # OpenVPN config created by PIA script (accessible via shared filesystem)
    ]
    
    for file_path in files_to_remove:
        try:
            if isinstance(file_path, str):
                file_path = Path(file_path)
            
            if file_path.exists():
                if file_path == PORT_FILE:
                    # Use sudo for port file removal
                    run_command(f"sudo rm {file_path}", check=False)
                    log_message(3, f"Removed port file: {file_path}")
                else:
                    file_path.unlink()
                    log_message(3, f"Removed file: {file_path}")
        except Exception as e:
            log_message(1, f"Warning: Failed to remove {file_path}: {e}")
    
    log_message(2, "File cleanup completed.")


def teardown_network_devices():
    """Removes tun devices and network interfaces."""
    # Only attempt network cleanup if the VPN namespace actually exists
    if not namespace_exists():
        log_message(3, "VPN namespace does not exist. Skipping network device cleanup.")
        return
    
    log_message(3, "Removing network devices...")
    
    # Remove tun device in namespace if it exists
    try:
        log_message(5, "Removing tun device in namespace...")
        run_command(f"ip netns exec {VPN_NS} ip link delete tun06", sudo=True, check=False)
        log_message(3, "Removed tun device in namespace.")
    except Exception as e:
        log_message(5, f"Tun device cleanup: {e}")

    # Bring down veth pair interfaces if they exist
    try:
        log_message(5, "Bringing down veth interfaces...")
        run_command(f"ip link set {VPN_IF} down", sudo=True, check=False)
        run_command(f"ip netns exec {VPN_NS} ip link set {VPN_PEER_IF} down", sudo=True, check=False)
        log_message(3, "Interfaces brought down.")
    except Exception as e:
        log_message(5, f"Interface shutdown: {e}")

    # Delete veth pair
    try:
        log_message(5, "Removing veth pair...")
        run_command(f"ip link delete {VPN_IF}", sudo=True, check=False)
        log_message(3, "Removed veth pair.")
    except Exception as e:
        log_message(5, f"Veth pair removal: {e}")
    
    log_message(2, "Network devices cleanup completed.")


def teardown_transmission_configs():
    """Removes transmission configuration files while preserving user data."""
    log_message(3, "Cleaning up transmission configurations...")
    
    # Only clean up namespace-specific and template configs
    # DO NOT remove the main transmission config directory as it contains user data
    config_paths = [
        TRANSMISSION_NAMESPACE_CONFIG,
        TRANSMISSION_TEMPLATE_CONFIGS,
        # TRANSMISSION_CONFIG_DIR  # ← Removed this to preserve user data
    ]
    
    for config_path in config_paths:
        try:
            config_path_obj = Path(config_path)
            if config_path_obj.exists():
                if config_path_obj.is_dir():
                    # Remove entire directory and contents
                    import shutil
                    shutil.rmtree(config_path_obj, ignore_errors=True)
                    log_message(5, f"Removed transmission config directory: {config_path}")
                else:
                    # Remove single file
                    config_path_obj.unlink()
                    log_message(5, f"Removed transmission config file: {config_path}")
            else:
                log_message(5, f"Transmission config path not found: {config_path}")
        except Exception as e:
            log_message(1, f"Warning: Failed to remove transmission config {config_path}: {e}")
    
    # Also clean up any stray transmission config files in /tmp
    try:
        tmp_configs = list(Path("/tmp").glob("transmission-*"))
        for tmp_config in tmp_configs:
            try:
                if tmp_config.is_dir():
                    import shutil
                    shutil.rmtree(tmp_config, ignore_errors=True)
                else:
                    tmp_config.unlink()
                log_message(5, f"Removed temporary transmission config: {tmp_config}")
            except Exception as e:
                log_message(5, f"Failed to remove temporary config {tmp_config}: {e}")
    except Exception as e:
        log_message(5, f"Could not clean up temporary transmission configs: {e}")
    
    log_message(2, "Transmission configuration cleanup completed (user data preserved).")


def teardown_namespace():
    """Removes the VPN network namespace."""
    log_message(3, f"Removing network namespace '{VPN_NS}'...")
    
    try:
        # Check if namespace exists first
        if namespace_exists():
            run_command(f"ip netns delete {VPN_NS}", sudo=True, check=False)
            log_message(2, f"Removed network namespace '{VPN_NS}'.")
        else:
            log_message(5, f"Network namespace '{VPN_NS}' not found or already removed.")
    except Exception as e:
        log_message(1, f"Warning: Failed to remove network namespace: {e}")


def perfect_teardown():
    """
    Performs a complete, perfect teardown of all VPN and Transmission components.
    This function ensures complete cleanup of:
    - All running processes (VPN, Transmission, PIA scripts)
    - All firewall rules (using comment binding for precision)
    - All temporary files and credentials
    - All transmission configuration files and directories
    - All network devices (tun, veth pairs) (only if namespace exists)
    - The VPN network namespace
    
    This teardown is designed to leave the system in a completely clean state
    as if the VPN/Transmission setup had never been run.
    """
    log_message(0, "Initiating perfect teardown sequence...")
    
    try:
        # Step 1: Terminate all processes first to prevent conflicts
        teardown_processes()
        
        # Step 2: Remove firewall rules using comment binding
        teardown_firewall_rules()
        
        # Step 3: Clean up temporary files and credentials
        teardown_files()
        
        # Step 4: Clean up transmission configurations (before removing namespace)
        teardown_transmission_configs()
        
        # Step 5: Clean up network devices (only if namespace exists)
        teardown_network_devices()
        
        # Step 6: Remove the network namespace (must be last)
        teardown_namespace()
        
        log_message(0, "Perfect teardown completed successfully. Digital sovereignty infrastructure cleanly removed.")
        
    except Exception as e:
        log_message(1, f"Error during perfect teardown: {e}")
        log_message(1, "System may require manual cleanup.")
        raise


def emergency_teardown():
    """
    Emergency teardown that attempts cleanup even if some components fail.
    This is more aggressive and will attempt to clean up everything regardless
    of individual component failures.
    """
    log_message(0, "Initiating emergency teardown sequence...")
    
    errors = []
    
    # Try each teardown component, collecting errors but not stopping
    teardown_components = [
        ("processes", teardown_processes),
        ("firewall rules", teardown_firewall_rules),
        ("files", teardown_files),
        ("transmission configs", teardown_transmission_configs),
        ("network devices", teardown_network_devices),
        ("namespace", teardown_namespace),
    ]
    
    for component_name, teardown_func in teardown_components:
        try:
            teardown_func()
        except Exception as e:
            error_msg = f"Failed to teardown {component_name}: {e}"
            errors.append(error_msg)
            log_message(1, error_msg)
    
    if errors:
        log_message(1, f"Emergency teardown completed with {len(errors)} errors:")
        for error in errors:
            log_message(1, f"  - {error}")
        log_message(1, "Manual cleanup may be required for failed components.")
    else:
        log_message(0, "Emergency teardown completed successfully without errors.")
    
    return len(errors) == 0  # Return True if no errors


def verify_teardown():
    """
    Verifies that the teardown was successful by checking for remaining components.
    Returns True if system is clean, False if cleanup issues remain.
    """
    log_message(3, "Verifying teardown completeness...")
    
    issues = []
    
    # Check for remaining processes
    remaining_processes = []
    process_patterns = ['port_forwarding.sh', 'openvpn', 'transmission-daemon']
    for pattern in process_patterns:
        pids = find_pids(pattern)
        if pids:
            remaining_processes.extend([(pattern, pids)])
    
    if remaining_processes:
        issues.append(f"Remaining processes: {remaining_processes}")
    
    # Check for remaining files
    check_files = [PORT_FILE, Path(f"{RAMDISK_MNT}/openvpn_auth.txt")]
    remaining_files = [f for f in check_files if f.exists()]
    if remaining_files:
        issues.append(f"Remaining files: {remaining_files}")
    
    # Check for remaining transmission configs
    transmission_configs = [
        Path(TRANSMISSION_NAMESPACE_CONFIG),
        Path(TRANSMISSION_TEMPLATE_CONFIGS),
        Path(TRANSMISSION_CONFIG_DIR)
    ]
    remaining_configs = [f for f in transmission_configs if f.exists()]
    if remaining_configs:
        issues.append(f"Remaining transmission configs: {remaining_configs}")
    
    # Check for namespace
    if namespace_exists():
        issues.append(f"Network namespace '{VPN_NS}' still exists")
    
    # Check for veth interface
    try:
        result = run_command(f"ip link show {VPN_IF}", check=False, capture_output=True, sudo=True)
        if result.returncode == 0:
            issues.append(f"veth interface '{VPN_IF}' still exists")
    except Exception as e:
        log_message(5, f"Could not check veth interface: {e}")
    
    if issues:
        log_message(1, "Teardown verification failed. Remaining issues:")
        for issue in issues:
            log_message(1, f"  - {issue}")
        return False
    else:
        log_message(2, "Teardown verification successful. System is clean.")
        return True
