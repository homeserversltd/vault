#!/usr/bin/env python3

"""
Standalone Perfect Teardown Script for HOMESERVER VPN/Transmission Infrastructure

This script provides a standalone way to perform complete teardown of VPN and Transmission
components without needing to run the full transmissionLauncher.py script.

Usage:
    python3 teardown_standalone.py [--emergency] [--verify-only] [--verbose LEVEL]
    
Options:
    --emergency     Use emergency teardown mode (more aggressive, continues on errors)
    --verify-only   Only verify if system is clean, don't perform teardown
    --verbose       Set verbosity level (0-5, default 3)
"""

import argparse
import sys
import os
from pathlib import Path

# Import the teardown components
from setup import (
    setup_logging,
    perfect_teardown, emergency_teardown, verify_teardown
)


def main():
    """Main function for standalone teardown script."""
    parser = argparse.ArgumentParser(
        description="Standalone perfect teardown for HOMESERVER VPN/Transmission infrastructure"
    )
    parser.add_argument(
        "--emergency",
        action="store_true",
        help="Use emergency teardown mode (more aggressive, continues on errors)"
    )
    parser.add_argument(
        "--verify-only",
        action="store_true", 
        help="Only verify if system is clean, don't perform teardown"
    )
    parser.add_argument(
        "--verbose",
        type=int,
        default=3,
        choices=range(6),
        help="Set verbosity level (0=STATUS, 1=ERROR, 2=SUCCESS, 3=INFO, 4=VARIABLES, 5=DEBUG). Default is 3."
    )
    args = parser.parse_args()

    # Initialize logging and import log_message
    setup_logging(args.verbose)
    from setup.logger import log_message

    # Check root privileges
    if os.geteuid() != 0:
        try:
            # Simple sudo check
            import subprocess
            subprocess.run(["sudo", "-nv"], check=True, capture_output=True)
            log_message(3, "Sudo privileges appear available.")
        except Exception:
            log_message(1, "This script requires root privileges or passwordless sudo access.")
            sys.exit(1)

    if args.verify_only:
        log_message(0, "Performing teardown verification only...")
        if verify_teardown():
            log_message(0, "System is clean - no VPN/Transmission components found.")
            sys.exit(0)
        else:
            log_message(1, "System is not clean - VPN/Transmission components still present.")
            sys.exit(1)

    if args.emergency:
        log_message(0, "Performing emergency teardown...")
        try:
            success = emergency_teardown()
            if success:
                log_message(0, "Emergency teardown completed successfully.")
                if verify_teardown():
                    log_message(0, "Teardown verification successful.")
                    sys.exit(0)
                else:
                    log_message(1, "Teardown verification failed despite successful emergency teardown.")
                    sys.exit(1)
            else:
                log_message(1, "Emergency teardown completed with errors.")
                sys.exit(1)
        except Exception as e:
            log_message(1, f"Emergency teardown failed: {e}")
            sys.exit(1)
    else:
        log_message(0, "Performing perfect teardown...")
        try:
            perfect_teardown()
            if verify_teardown():
                log_message(0, "Perfect teardown completed successfully. System is clean.")
                sys.exit(0)
            else:
                log_message(1, "Perfect teardown completed but verification failed. Attempting emergency teardown...")
                if emergency_teardown():
                    log_message(0, "Emergency teardown successful after perfect teardown issues.")
                    sys.exit(0)
                else:
                    log_message(1, "Both perfect and emergency teardown had issues.")
                    sys.exit(1)
        except Exception as e:
            log_message(1, f"Perfect teardown failed: {e}. Attempting emergency teardown...")
            try:
                if emergency_teardown():
                    log_message(0, "Emergency teardown successful after perfect teardown failure.")
                    sys.exit(0)
                else:
                    log_message(1, "Emergency teardown also had issues.")
                    sys.exit(1)
            except Exception as emergency_e:
                log_message(1, f"Both perfect and emergency teardown failed: {e}, {emergency_e}")
                sys.exit(1)


if __name__ == "__main__":
    main()
