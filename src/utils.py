#!/usr/bin/env python3

import subprocess
import os
import random
import re
import sys
from pathlib import Path
# Safe logging function that falls back to print
def safe_log(level, message):
    try:
        from .logger import log_message
        if log_message is not None:
            log_message(level, message)
        else:
            print(f"[{level}] {message}")
    except (ImportError, AttributeError):
        print(f"[{level}] {message}")

# Alias for backward compatibility
log_message = safe_log

# --- Configuration ---
VAULT_DIR = Path("/vault")
KEYS_DIR = VAULT_DIR / ".keys"
KEY_EXCHANGE_DIR = Path("/mnt/keyexchange")
KEYMAN_SCRIPT = VAULT_DIR / "keyman" / "exportkey.sh"


def run_command(command, check=True, capture_output=False, text=True, timeout=None, sudo=True, shell=False, env=None, cwd=None, netns=None):
    """Runs a shell command, optionally with sudo and in a network namespace."""
    full_command = []
    if netns:
        full_command.extend(["sudo", "ip", "netns", "exec", netns])
    elif sudo:
        full_command.append("sudo")

    if isinstance(command, list):
        full_command.extend(command)
    else:
         # If shell=True, command should be a string
         if shell:
             full_command.append(command)
         else:
             full_command.extend(command.split())

    cmd_str = ' '.join(full_command) if not shell else full_command[-1] # Log the command string
    log_message(5, f"Running command: {cmd_str}")

    try:
        result = subprocess.run(
            full_command if not shell else cmd_str, # Pass string if shell=True
            check=check,
            capture_output=capture_output,
            text=text,
            timeout=timeout,
            shell=shell, # Use shell=True carefully
            env=env,
            cwd=cwd
        )
        if capture_output:
            # Only log output if it's not too long to avoid verbose logging
            stdout_output = result.stdout.strip()
            stderr_output = result.stderr.strip()
            
            if len(stdout_output) > 200:  # If output is longer than 200 chars, just log summary
                log_message(5, f"Command output: [TRUNCATED - {len(stdout_output)} chars] {stdout_output[:100]}...")
            else:
                log_message(5, f"Command output: {stdout_output}")
                
            if stderr_output:
                if len(stderr_output) > 200:
                    log_message(5, f"Command error : [TRUNCATED - {len(stderr_output)} chars] {stderr_output[:100]}...")
                else:
                    log_message(5, f"Command error : {stderr_output}")
        return result
    except subprocess.CalledProcessError as e:
        log_message(1, f"Command failed: {cmd_str}")
        log_message(1, f"Error: {e}")
        log_message(1, f"Stderr: {e.stderr.strip() if e.stderr else 'N/A'}")
        raise # Re-raise the exception if check=True
    except subprocess.TimeoutExpired as e:
        log_message(1, f"Command timed out: {cmd_str}")
        raise
    except Exception as e:
        log_message(1, f"Failed to run command '{cmd_str}'. Error: {e}")
        raise


def read_credentials(utility_name):
    """Reads credentials using keyman script."""
    key_file = KEY_EXCHANGE_DIR / utility_name
    
    log_message(3, f"Attempting to export credentials for {utility_name}...")
    try:
        # Run exportkey.sh with sudo
        run_command([str(KEYMAN_SCRIPT), utility_name], sudo=True)
    except Exception as e:
        log_message(1, f"Failed to execute exportkey.sh for {utility_name}. Error: {e}")
        sys.exit(1)

    if not key_file.is_file():
        log_message(1, f"Failed to get credentials for {utility_name} at {key_file}")
        sys.exit(1)

    utility_creds = {}
    try:
        # Read the key file with sudo since it was created with sudo
        result = run_command(f"cat {key_file}", sudo=True, capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if '=' in line:
                key, temp_value = line.split('=', 1)
                key = key.strip()
                # More carefully handle quoted values
                value = temp_value.strip()
                # Remove surrounding quotes if present
                if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                
                utility_creds[key] = value
                if key.lower() == 'username':
                    log_message(4, f"Read {utility_name} username: {value}")
                elif key.lower() == 'password':
                    log_message(4, f"Read {utility_name} password: [REDACTED]")
                    # Debug the actual password format to help troubleshoot 
                    log_message(5, f"Password format check - length: {len(value)}, raw value: {value}")
                    
        log_message(2, f"Successfully read credentials for {utility_name}.")
        
        # Additional verification
        if 'username' not in utility_creds or 'password' not in utility_creds:
            log_message(1, f"Warning: Failed to find username/password in credentials for {utility_name}")
            
    except Exception as e:
        log_message(1, f"Error reading credential file {key_file}: {e}")
        sys.exit(1)
    finally:
         # Clean up the key file for security
        try:
            key_file.unlink()
            log_message(3, f"Removed credential file {key_file}.")
        except OSError as e:
            log_message(1, f"Warning: Failed to remove credential file {key_file}: {e}")
    
    return utility_creds


def generate_compliant_mac_address():
    """Generates a random MAC address compliant with local assignment."""
    mac_bytes = [random.randint(0x00, 0xff) for _ in range(6)]
    
    # Set Locally Administered Address bit (bit 1 of first byte)
    # Clear Multicast Address bit (bit 0 of first byte)
    mac_bytes[0] = (mac_bytes[0] | 0x02) & 0xFE 
    
    mac_address = ':'.join(f'{byte:02x}' for byte in mac_bytes)
    log_message(5, f"Generated compliant MAC: {mac_address}")
    return mac_address


def remove_rules_by_comment(family, table, chain, comment):
    """Removes nftables rules matching a specific comment."""
    log_message(3, f"Attempting to remove rules with comment: '{comment}' from {chain} chain in {table} table of {family} family.")
    try:
        # List rules with handles and comments - capture output but don't log it verbosely
        result = run_command(f"sudo nft -a list table {family} {table}", check=True, capture_output=True, shell=True)
        lines = result.stdout.splitlines()
        
        # Only log a summary of what we found, not the entire nftables output
        log_message(5, f"Retrieved {len(lines)} lines from nftables table {family} {table}")
        
        handles_to_delete = []
        # Regex to find lines with the target comment and extract the handle
        # Example line: '... meta nfproto ipv4 ... comment "the_comment" # handle 123'
        comment_pattern = re.compile(r'.*comment\s+"' + re.escape(comment) + r'".*#\s+handle\s+(\d+)', re.IGNORECASE)

        for line in lines:
             # Check if the line belongs to the target chain (simple check, might need refinement)
            if f"chain {chain}" in line or chain in line.split('{')[0]: # Basic check if chain name appears before rule details
                 match = comment_pattern.search(line)
                 if match:
                     handles_to_delete.append(match.group(1))

        if not handles_to_delete:
            log_message(1, f"Warning, no rule found with comment: '{comment}' in {chain} chain of the table {table} of the family {family}. Nothing to remove.")
            return

        log_message(4, f"Preparing to remove rules with handles {handles_to_delete} from {chain} chain. Comment: '{comment}'.")

        for handle in handles_to_delete:
            log_message(3, f"Removing rule with handle: {handle} and comment: '{comment}'.")
            try:
                run_command(f"sudo nft delete rule {family} {table} {chain} handle {handle}", shell=True)
                log_message(2, f"Successfully removed rule with handle: {handle}.")
            except Exception as e:
                 # Log error but continue trying to remove others
                log_message(1, f"Failed to remove rule with handle: {handle}. Error: {e}. Ensure table, chain, and handle are correct.")

    except Exception as e:
        log_message(1, f"Error occurred while trying to remove rules by comment '{comment}': {e}")


def terminate_processes(pids):
    """Attempts to terminate a list of processes by PID."""
    for pid in pids:
        pid = pid.strip()
        if pid:
            try:
                pid_int = int(pid)
                # Check if process exists (simple check)
                os.kill(pid_int, 0) 
                log_message(3, f"Terminating process (PID: {pid_int}).")
                run_command(f"sudo kill {pid_int}", check=False) # Don't check=True, kill can fail if already exited
                log_message(2, f"Attempted termination for process (PID: {pid_int}).")
            except ProcessLookupError:
                 log_message(5, f"Process not found (PID: {pid}). Already terminated?")
            except ValueError:
                 log_message(1, f"Invalid PID found: {pid}")
            except PermissionError:
                 log_message(1, f"Permission denied to signal process (PID: {pid_int}).")
            except Exception as e:
                 log_message(1, f"Failed to terminate process (PID: {pid_int}). Error: {e}")


def find_pids(process_name_pattern):
    """Finds PIDs matching a pattern using pgrep."""
    try:
        # Use pgrep -f to match against the full command line
        # Note: When searching for processes in namespaces, we can't use the namespace in the pattern
        # as pgrep won't find it that way, so we need to strip that part from the pattern if it exists
        if 'ip netns exec' in process_name_pattern:
            # Extract just the command name without the namespace prefix
            parts = process_name_pattern.split()
            if len(parts) > 3 and parts[0:3] == ['ip', 'netns', 'exec']:
                # Reconstruct the pattern without the namespace part
                process_name_pattern = ' '.join(parts[4:])
        
        result = run_command(f"pgrep -f '{process_name_pattern}'", sudo=False, check=False, capture_output=True)
        if result.returncode == 0 and result.stdout:
            pids = result.stdout.strip().splitlines()
            log_message(5, f"Found PIDs for '{process_name_pattern}': {pids}")
            return pids
        else:
            log_message(5, f"No PIDs found for '{process_name_pattern}'.")
            return []
    except Exception as e:
        log_message(1, f"Error running pgrep for '{process_name_pattern}': {e}")
        return []
