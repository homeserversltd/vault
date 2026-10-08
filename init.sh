#!/bin/bash

# Debug logging setup
DEBUG_LOG="/tmp/init_homeserver.log"
DEBUG_ENABLED=true

# Function to log debug messages
debug_log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    if [[ "$DEBUG_ENABLED" == "true" ]]; then
        echo "[$timestamp] DEBUG: $message" | tee -a "$DEBUG_LOG"
    fi
}

# Function to log error messages
error_log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] ERROR: $message" | tee -a "$DEBUG_LOG" >&2
}

# Function to log info messages
info_log() {
    local message="$1"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] INFO: $message" | tee -a "$DEBUG_LOG"
}

# Initialize debug log
if [[ "$DEBUG_ENABLED" == "true" ]]; then
    echo "=== INIT.SH DEBUG LOG STARTED $(date) ===" > "$DEBUG_LOG"
    debug_log "Script started"
fi

declare -A script_status

# Validate that the vault mount is available
validate_mounts() {
    debug_log "Starting mount validation"

    if ! mountpoint -q /vault; then
        error_log "/vault is not mounted"
        return 1
    else
        debug_log "/vault is properly mounted"
    fi

    debug_log "Mount validation completed successfully"
    return 0
}

# Function to print the portal service summary
print_final_report() {
    echo -e "\n╔════════════════════════════════════════╗"
    echo -e "║          System Startup Report          ║"
    echo -e "╠════════════════════════════════════════╣"

    local services_started=0
    local services_total=0
    for status in "${script_status[@]}"; do
        ((services_total++))
        if [ "$status" = "Started" ]; then
            ((services_started++))
        fi
    done
    printf "║ Services: %2d/%2d started               ║\n" "$services_started" "$services_total"
    echo -e "╚════════════════════════════════════════╝"
}

# Select the first readable appliance config containing valid JSON.
resolve_appliance_config() {
    local candidate candidate_services
    for candidate in /etc/appliance/config.json /etc/appliance/config.factory; do
        if [[ ! -e "$candidate" && ! -L "$candidate" ]]; then
            continue
        fi
        if [[ ! -f "$candidate" || ! -r "$candidate" ]]; then
            error_log "Appliance config is not a readable regular file: $candidate"
            continue
        fi
        if ! candidate_services=$(jq -r 'if type == "object" then .tabs.portals.data.portals[]? | .services[]? else error("configuration root must be an object") end' "$candidate"); then
            error_log "Appliance config is not valid JSON object data: $candidate"
            continue
        fi
        config_path="$candidate"
        portal_services="$candidate_services"
        return 0
    done
    return 1
}

# Check if init.sh is already running to prevent concurrent execution
INIT_LOCK="/var/run/init_homeserver.lock"
if [ -f "$INIT_LOCK" ]; then
    lock_pid=$(cat "$INIT_LOCK" 2>/dev/null)
    if [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null; then
        info_log "init.sh is already running (PID: $lock_pid), exiting"
        exit 0
    else
        debug_log "Removing stale lock file (PID $lock_pid no longer exists)"
        rm -f "$INIT_LOCK"
    fi
fi

# Create lock file
echo $$ > "$INIT_LOCK"

# Cleanup function
cleanup_init() {
    rm -f "$INIT_LOCK"
}
trap cleanup_init EXIT INT TERM

# Main startup sequence
info_log "Starting system initialization..."

# Validate the vault mount first
if ! validate_mounts; then
    error_log "Mount validation failed. Exiting."
    exit 1
fi

debug_log "Creating /mnt/ramdisk/logs directory"
mkdir -p /mnt/ramdisk/logs

# Start enabled portal services from config
debug_log "Checking and starting enabled portal systemd services..."

# Resolve and read the enabled portal services from the appliance config.
if ! command -v jq &> /dev/null; then
    error_log "jq command not found. Skipping portal service checks. Please install jq."
elif ! resolve_appliance_config; then
    error_log "No valid readable appliance configuration found. Skipping portal service checks."
else
    debug_log "Using config path: $config_path"
    # Keep the loop in this shell so script_status remains available to the report.
    while IFS= read -r service_name; do
        if [ -z "$service_name" ]; then
            continue
        fi

        if [[ ! "$service_name" == *.service ]]; then
            service_unit="${service_name}.service"
        else
            service_unit="$service_name"
        fi

        debug_log "Checking service unit: $service_unit"
        if systemctl is-enabled --quiet "$service_unit"; then
            debug_log "$service_unit is enabled, resetting failed state..."
            systemctl reset-failed "$service_unit"

            debug_log "Attempting to start $service_unit..."
            if sudo systemctl start "$service_unit"; then
                info_log "Started $service_unit"
                script_status["$service_name"]="Started"
            else
                start_error=$?
                error_log "Failed to start $service_unit (exit code: $start_error)"
                script_status["$service_name"]="Start Failed"
            fi
        else
            debug_log "$service_unit is not enabled, skipping start."
            script_status["$service_name"]="Not Enabled"
        fi
    done <<< "$portal_services"
fi

debug_log "Portal service startup completed"

# Print final report
debug_log "Printing final report"
print_final_report

debug_log "System initialization completed"
exit 0
