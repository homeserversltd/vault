#!/usr/bin/env python3

import logging
import sys
from pathlib import Path

# --- Logging Configuration ---
RAMDISK_MNT = Path("/mnt/ramdisk")
LOGS_DIR = RAMDISK_MNT / "logs"
LOG_FILE = LOGS_DIR / "transmission.log"

LOG_LEVELS = {
    5: logging.DEBUG,      # DEBUG
    4: logging.DEBUG,      # VARIABLES (Mapped to DEBUG)
    3: logging.INFO,       # INFO
    2: logging.INFO,       # SUCCESS (Mapped to INFO)
    1: logging.ERROR,      # ERROR
    0: logging.INFO,       # STATUS (Mapped to INFO)
}

# Global log_message function
log_message = None

def setup_logging(verbosity_level):
    """Configures logging based on the provided verbosity level."""
    global log_message
    
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    LOG_FILE.touch(exist_ok=True)

    log_level = LOG_LEVELS.get(verbosity_level, logging.ERROR) # Default to ERROR
    
    # Adjust level names to match bash script somewhat
    logging.addLevelName(logging.DEBUG, "DEBUG")
    logging.addLevelName(logging.INFO, "INFO") # INFO/SUCCESS/STATUS map here
    logging.addLevelName(logging.ERROR, "ERROR")

    # Basic configuration
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        filename=LOG_FILE,
        filemode='a'
    )
    
    # Also log DEBUG messages to console if verbosity is 5 (DEBUG)
    if verbosity_level >= 5:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('DEBUG: %(message)s')
        console_handler.setFormatter(formatter)
        logging.getLogger().addHandler(console_handler)

    # Map Bash levels to logging calls for convenience
    def log_msg(level, message):
        actual_level = LOG_LEVELS.get(level)
        if actual_level:
            # Special handling for "VARIABLES" (level 4) and "SUCCESS" (level 2) if needed
            if level == 4:
                logging.debug(f"(VARIABLES) {message}")
            elif level == 2:
                logging.info(f"(SUCCESS) {message}")
            elif level == 0:
                 logging.info(f"(STATUS) {message}")
            else:
                logging.log(actual_level, message)
        # Always log STATUS (0) to info
        elif level == 0:
            logging.info(f"(STATUS) {message}")

    log_message = log_msg
    
    log_message(3, f"Logging initialized with verbosity level {verbosity_level} ({logging.getLevelName(log_level)}).")
    
    return log_message
