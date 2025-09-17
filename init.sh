#!/bin/bash

# Source Keyman utility functions
source /vault/keyman/utils.sh

# ============================================================================
# DRIVE DETECTION CONFIGURATION
# ============================================================================
# Set to "sda_boot" for SDA boot media scenarios (live homeserver)
# Set to "legacy_nvme" for original NVMe/SATA detection logic  
DRIVE_DETECTION_MODE="sda_boot"

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
    debug_log "Script started with DRIVE_DETECTION_MODE=$DRIVE_DETECTION_MODE"
fi

# Arrays to store status information
declare -A mounted_drives
declare -A script_status

# Validate required mount points
validate_mounts() {
    debug_log "Starting mount validation"
    
    # Check if /vault exists and is mounted
    if ! mountpoint -q /vault; then
        error_log "/vault is not mounted"
        return 1
    else
        debug_log "/vault is properly mounted"
    fi

    # Create /mnt/nas if it doesn't exist
    if [[ ! -d "/mnt/nas" ]]; then
        debug_log "Creating /mnt/nas directory"
        mkdir -p /mnt/nas
    else
        debug_log "/mnt/nas directory already exists"
    fi

    debug_log "Mount validation completed successfully"
    return 0
}

# Function to validate if a drive is NAS-compatible
validate_nas_compatibility() {
    local device=$1
    local device_name=$(basename "$device")
    
    debug_log "Validating NAS compatibility for $device"
    
    # Check if device block file exists
    if [[ ! -b "$device" ]]; then
        error_log "Device $device is not a block device"
        return 1
    fi
    
    # Check filesystem type with timeout to prevent hanging
    debug_log "Checking filesystem type for $device"
    local fstype
    fstype=$(timeout 10 sudo blkid -o value -s TYPE "$device" 2>/dev/null)
    local blkid_exit=$?
    
    if [[ $blkid_exit -eq 124 ]]; then
        error_log "blkid command timed out for $device (likely bad drive)"
        return 1
    elif [[ $blkid_exit -ne 0 ]]; then
        debug_log "blkid failed for $device (exit code: $blkid_exit)"
    fi
    
    if [[ -z "$fstype" ]]; then
        debug_log "No filesystem detected on $device, checking for LUKS encryption"
        # Check if encrypted with timeout
        if timeout 10 sudo cryptsetup isLuks "$device" 2>/dev/null; then
            debug_log "$device is LUKS encrypted, assuming NAS-compatible"
            return 0
        else
            local crypt_exit=$?
            if [[ $crypt_exit -eq 124 ]]; then
                error_log "cryptsetup isLuks timed out for $device (likely bad drive)"
                return 1
            else
                error_log "$device has no filesystem and is not encrypted"
                return 1
            fi
        fi
    fi
    
    # Validate filesystem type (XFS/EXT4 only, or LUKS encrypted)
    debug_log "Filesystem type for $device: $fstype"
    case "$fstype" in
        xfs|ext4)
            debug_log "$device has compatible filesystem: $fstype"
            return 0
            ;;
        crypto_LUKS)
            debug_log "$device is LUKS encrypted, assuming NAS-compatible"
            return 0
            ;;
        *)
            error_log "$device has incompatible filesystem: $fstype (need XFS/EXT4 or LUKS)"
            return 1
            ;;
    esac
}

# Function to detect and identify nas drives
detect_nas_drives() {
    local drives_found=0
    local root_device
    
    debug_log "Starting NAS drive detection"
    
    # Get the root device path
    root_device=$(findmnt -n -o SOURCE /)
    
    debug_log "Root device is: $root_device"
    debug_log "Drive detection mode: $DRIVE_DETECTION_MODE"
    
    # Make these variables global explicitly
    export nas_DRIVE=""
    export nas_BACKUP_DRIVE=""
    
    # Get candidate drives by scanning all available drives beyond boot drive
    local candidate_drives=()
    local boot_drive=""
    
    # Determine boot drive to exclude from candidates
    if [[ "$DRIVE_DETECTION_MODE" == "sda_boot" ]]; then
        debug_log "SDA boot mode - Excluding sda, scanning all other drives"
        boot_drive="sda"
    elif [[ "$DRIVE_DETECTION_MODE" == "legacy_nvme" ]]; then
        if [[ "$root_device" =~ nvme ]]; then
            debug_log "Legacy mode - Root is on NVMe, scanning all SATA drives"
            boot_drive=""  # No SATA boot drive to exclude
        else
            debug_log "Legacy mode - Root is on SATA, excluding root drive from scan"
            # Extract drive name from root device (e.g., /dev/sda1 -> sda)
            boot_drive=$(echo "$root_device" | sed 's|/dev/||' | sed 's|[0-9]*$||')
        fi
    else
        error_log "Unknown DRIVE_DETECTION_MODE: $DRIVE_DETECTION_MODE"
        error_log "Valid modes: 'sda_boot', 'legacy_nvme'"
        return 0
    fi
    
    # Scan for all available drives beyond 'a' (sdb, sdc, sdd, etc.)
    debug_log "Scanning for available drives (excluding boot drive: $boot_drive)"
    for drive_letter in {b..z}; do
        local drive_name="sd${drive_letter}"
        local device_path="/dev/${drive_name}"
        
        # Skip if this is the boot drive
        if [[ "$drive_name" == "$boot_drive" ]]; then
            debug_log "Skipping boot drive: $device_path"
            continue
        fi
        
        # Check if drive exists
        if [[ -b "$device_path" ]]; then
            debug_log "Found drive: $device_path"
            candidate_drives+=("$device_path")
        else
            debug_log "Drive $device_path does not exist"
        fi
    done
    
    debug_log "Found ${#candidate_drives[@]} candidate drives: ${candidate_drives[*]}"
    
    # First pass: collect all NAS-compatible drives with their sizes
    local compatible_drives=()
    for device in "${candidate_drives[@]}"; do
        debug_log "Checking candidate device: $device"
        if validate_nas_compatibility "$device"; then
            # Get drive size in bytes
            local size_bytes
            size_bytes=$(sudo blockdev --getsize64 "$device" 2>/dev/null)
            if [[ $? -eq 0 && -n "$size_bytes" ]]; then
                # Store as "size:device" for sorting
                compatible_drives+=("$size_bytes:$device")
                debug_log "$device is NAS-compatible with size: $size_bytes bytes"
            else
                debug_log "Could not determine size for $device, skipping"
            fi
        else
            debug_log "$device exists but is not NAS-compatible, skipping"
        fi
    done
    
    debug_log "Found ${#compatible_drives[@]} NAS-compatible drives"
    
    # Sort drives by size (largest first) and assign roles
    if [[ ${#compatible_drives[@]} -gt 0 ]]; then
        # Sort by size (numeric, reverse order for largest first)
        IFS=$'\n' sorted_drives=($(sort -nr -t: -k1 <<< "${compatible_drives[*]}"))
        
        # Extract device paths and assign roles
        for drive_entry in "${sorted_drives[@]}"; do
            local device="${drive_entry#*:}"  # Remove size prefix
            local size_bytes="${drive_entry%:*}"  # Extract size
            local size_gb=$((size_bytes / 1024 / 1024 / 1024))
            
            if [[ -z "$nas_DRIVE" ]]; then
                export nas_DRIVE="$device"
                ((drives_found++))
                debug_log "Assigned $device (${size_gb}GB) as primary NAS drive"
            elif [[ -z "$nas_BACKUP_DRIVE" ]]; then
                export nas_BACKUP_DRIVE="$device"
                ((drives_found++))
                debug_log "Assigned $device (${size_gb}GB) as backup NAS drive"
                break  # We only need two drives
            fi
        done
    fi
    
    debug_log "drives_found=$drives_found"
    debug_log "nas_DRIVE=$nas_DRIVE"
    debug_log "nas_BACKUP_DRIVE=$nas_BACKUP_DRIVE"
    
    return $drives_found
}

# Function to try simple mount first
mount_drive() {
    local device=$1
    local mount_point=$2
    
    debug_log "Starting mount_drive for device=$device, mount_point=$mount_point"
    
    # Check if the device is already mounted
    if findmnt -S "$device" >/dev/null; then
        debug_log "Device $device is already mounted"
        local current_mount=$(findmnt -S "$device" -n -o TARGET)
        debug_log "$device is already mounted at $current_mount"
        mounted_drives["$device"]="$current_mount"
        return 0
    else
        debug_log "Device $device is not currently mounted"
    fi
    
    # Create mount point if it doesn't exist
    if [[ ! -d "$mount_point" ]]; then
        debug_log "Creating mount point: $mount_point"
        sudo mkdir -p "$mount_point"
    else
        debug_log "Mount point $mount_point already exists"
    fi
    
    # Try simple mount first with timeout
    debug_log "Attempting simple mount of $device to $mount_point"
    if timeout 30 sudo mount "$device" "$mount_point" 2>/dev/null; then
        debug_log "Successfully mounted $device to $mount_point (unencrypted)"
        mounted_drives["$device"]="$mount_point"
        return 0
    else
        local mount_exit=$?
        debug_log "Simple mount failed (exit code: $mount_exit), checking if device is LUKS encrypted"
        # Check if device is LUKS encrypted with timeout
        if timeout 10 sudo cryptsetup isLuks "$device" 2>/dev/null; then
            debug_log "Device is LUKS encrypted, attempting encrypted mount"
            mount_encrypted_drive "$device" "$mount_point"
            return $?
        else
            local crypt_exit=$?
            if [[ $crypt_exit -eq 124 ]]; then
                error_log "cryptsetup isLuks timed out for $device (likely bad drive)"
            else
                error_log "Mount failed and device is not LUKS encrypted"
            fi
            mounted_drives["$device"]="FAILED"
            return 1
        fi
    fi
}

# Mount encrypted drives
mount_encrypted_drive() {
    local device=$1
    local mount_point=$2
    local mapper_name=$(basename "$device")_crypt

    debug_log "Starting encrypted mount process for $device using mountDrive.sh"
    debug_log "Using mapper name: $mapper_name"

    # Use mountDrive.sh to create proper systemd units
    debug_log "Calling mountDrive.sh to mount $device to $mount_point with mapper $mapper_name"
    
    /vault/scripts/mountDrive.sh mount "$device" "$mount_point" "$mapper_name"
    if [ $? -eq 0 ]; then
        debug_log "SUCCESS: mountDrive.sh successfully mounted $device to $mount_point"
        mounted_drives["$device"]="$mount_point"
        return 0
    else
        local mount_error=$?
        error_log "mountDrive.sh failed to mount $device (exit code: $mount_error)"
        mounted_drives["$device"]="FAILED"
        return 1
    fi
}

# Function to check if NAS drives are already mounted
check_existing_mounts() {
    debug_log "Checking for existing NAS mounts"
    
    local nas_mounted=false
    local backup_mounted=false
    
    # Check if /mnt/nas is already mounted
    if mountpoint -q "/mnt/nas" 2>/dev/null; then
        local nas_source=$(findmnt -n -o SOURCE "/mnt/nas" 2>/dev/null)
        debug_log "/mnt/nas is already mounted from: $nas_source"
        nas_mounted=true
    else
        debug_log "/mnt/nas is not mounted"
    fi
    
    # Check if /mnt/nas_backup is already mounted
    if mountpoint -q "/mnt/nas_backup" 2>/dev/null; then
        local backup_source=$(findmnt -n -o SOURCE "/mnt/nas_backup" 2>/dev/null)
        debug_log "/mnt/nas_backup is already mounted from: $backup_source"
        backup_mounted=true
    else
        debug_log "/mnt/nas_backup is not mounted"
    fi
    
    if [[ "$nas_mounted" == true || "$backup_mounted" == true ]]; then
        info_log "NAS drives already mounted, skipping mount operations"
        debug_log "nas_mounted=$nas_mounted, backup_mounted=$backup_mounted"
        return 0  # Already mounted, no need to proceed
    fi
    
    return 1  # Not mounted, proceed with detection and mounting
}

# Function to handle nas drive mounting
handle_nas_drives() {
    debug_log "Starting NAS drive handling"
    
    # Check if drives are already mounted first
    if check_existing_mounts; then
        debug_log "Drives already mounted, skipping mount operations"
        return 0
    fi
    
    detect_nas_drives
    local drives_found=$?

    debug_log "detect_nas_drives returned: $drives_found"
    debug_log "nas_DRIVE=$nas_DRIVE"
    debug_log "nas_BACKUP_DRIVE=$nas_BACKUP_DRIVE"

    # No fallback needed - comprehensive scan already checked all available drives
    if [[ $drives_found -eq 0 ]]; then
        info_log "No NAS-compatible drives found after scanning all available drives"
        debug_log "Available drives were: ${candidate_drives[*]:-none}"
    else
        info_log "Successfully identified $drives_found NAS-compatible drive(s)"
    fi

    local mount_errors=0

    if [ -n "$nas_DRIVE" ]; then
        debug_log "Attempting to mount main nas drive: $nas_DRIVE"

        # Export nas key if it exists
        if [ -f "/vault/.keys/nas.key" ]; then
            debug_log "Exporting nas key..."
            /vault/keyman/exportkey.sh nas || error_log "Failed to export nas key"
            # Load environment variables from exported key
            if [ -f "/mnt/keyexchange/nas" ]; then
                debug_log "Loading nas key environment variables"
                source /mnt/keyexchange/nas
            fi
        else
            debug_log "No nas.key found in /vault/.keys/"
        fi

        # Attempt to mount (mount_drive will handle encrypted/unencrypted)
        mount_drive "$nas_DRIVE" "/mnt/nas"
        if [ $? -ne 0 ]; then
            error_log "Failed to mount primary NAS drive: $nas_DRIVE"
            ((mount_errors++))
        else
            debug_log "Successfully mounted primary NAS drive: $nas_DRIVE"
        fi
    else
        info_log "No NAS-compatible drives detected for mounting"
        ((mount_errors++))
    fi
    
    if [ -n "$nas_BACKUP_DRIVE" ]; then
        debug_log "Attempting to mount backup nas drive: $nas_BACKUP_DRIVE"
        
        # Export nas_backup key if it exists
        if [ -f "/vault/.keys/nas_backup.key" ]; then
            debug_log "Exporting nas_backup key..."
            /vault/keyman/exportkey.sh nas_backup || error_log "Failed to export nas_backup key"
             # Load environment variables from exported key
            if [ -f "/mnt/keyexchange/nas_backup" ]; then
                debug_log "Loading nas_backup key environment variables"
                source /mnt/keyexchange/nas_backup
            fi
        else
            debug_log "No nas_backup.key found in /vault/.keys/"
        fi

        # Attempt to mount (mount_drive will handle encrypted/unencrypted)
        mount_drive "$nas_BACKUP_DRIVE" "/mnt/nas_backup"
         if [ $? -ne 0 ]; then
            error_log "Failed to mount backup NAS drive: $nas_BACKUP_DRIVE"
            ((mount_errors++))
        else
            debug_log "Successfully mounted backup NAS drive: $nas_BACKUP_DRIVE"
        fi
    else
        debug_log "No backup NAS drive to mount"
    fi

    debug_log "Finished with $mount_errors mount errors"
    return $mount_errors
}

# Function to print final report
print_final_report() {
    local nas_status=$1
    
    echo -e "\n╔════════════════════════════════════════╗"
    echo -e "║          System Startup Report          ║"
    echo -e "╠════════════════════════════════════════╣"
    
    # Drive Status Section
    echo -e "║ Drive Mounts:                           ║"
    for drive in "${!mounted_drives[@]}"; do
        local status_symbol
        local mount_point="${mounted_drives[$drive]}"
        local drive_name=$(basename "$drive")
        
        if [ "${mounted_drives[$drive]}" = "FAILED" ]; then
            status_symbol="❌"
            printf "║ %s %-12s: Mount failed          ║\n" "$status_symbol" "$drive_name"
        else
            status_symbol="✓"
            printf "║ %s %-12s: %-20s ║\n" "$status_symbol" "$drive_name" "$mount_point"
        fi
    done
    
    # Service Summary
    echo -e "╟────────────────────────────────────────╢"
    local services_started=0
    local services_total=0
    for status in "${script_status[@]}"; do
        ((services_total++))
        if [ "$status" = "Started" ]; then
            ((services_started++))
        fi
    done
    printf "║ Services: %2d/%2d started               ║\n" "$services_started" "$services_total"
    
    # Overall Status
    echo -e "╟────────────────────────────────────────╢"
    if [ $nas_status -eq 0 ]; then
        echo -e "║ ✓ All systems initialized successfully  ║"
    elif [ $nas_status -eq 255 ]; then
        echo -e "║ ℹ No NAS drives detected               ║"
    else
        echo -e "║ ⚠ Some operations failed               ║"
    fi
    echo -e "╚════════════════════════════════════════╝"
}

# Check if init.sh is already running to prevent concurrent execution
INIT_LOCK="/var/run/init_homeserver.lock"
if [ -f "$INIT_LOCK" ]; then
    local lock_pid=$(cat "$INIT_LOCK" 2>/dev/null)
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

# Validate mounts first
if ! validate_mounts; then
    error_log "Mount validation failed. Exiting."
    exit 1
fi

debug_log "Creating /mnt/ramdisk/logs directory"
mkdir -p /mnt/ramdisk/logs

# Handle nas drives
debug_log "Starting NAS drive handling"
handle_nas_drives
nas_status=$?
debug_log "NAS drive handling completed with status: $nas_status"

# Start enabled portal services from config
debug_log "Checking and starting enabled portal systemd services..."

# Get the valid config path using factoryFallback.sh
config_path=$(/usr/local/sbin/factoryFallback.sh)
if [ $? -ne 0 ]; then
    error_log "Failed to get valid config path. Skipping portal service checks."
elif ! command -v jq &> /dev/null; then
    error_log "jq command not found. Skipping portal service checks. Please install jq."
else
    debug_log "Using config path: $config_path"
    # Use jq to extract systemd services from portals
    # Iterate over each portal and get its services array
    # Note: type field indicates oneshot vs simple service behavior, not launch method
    jq -c '.tabs.portals.data.portals[] | .services[]?' "$config_path" | while read -r service_name_jq; do
        # Remove quotes added by jq
        service_name=$(echo "$service_name_jq" | tr -d '"')
        
        if [ -z "$service_name" ]; then
            continue # Skip empty service names
        fi

        # Append .service if not present (though systemctl usually handles this)
        if [[ ! "$service_name" == *.service ]]; then
            service_unit="${service_name}.service"
        else
             service_unit="$service_name"
        fi

        debug_log "Checking service unit: $service_unit"
        if systemctl is-enabled --quiet "$service_unit"; then
            debug_log "$service_unit is enabled, resetting failed state..."
            systemctl reset-failed "$service_unit"  # Clear any previous failure state

            debug_log "Attempting to start $service_unit..."
            if sudo systemctl start "$service_unit"; then
                info_log "Started $service_unit"
                script_status["$service_name"]="Started"
            else
                local start_error=$?
                error_log "Failed to start $service_unit (exit code: $start_error)"
                script_status["$service_name"]="Start Failed"
            fi
        else
            debug_log "$service_unit is not enabled, skipping start."
            script_status["$service_name"]="Not Enabled"
        fi
    done <<< "$(jq -c '.tabs.portals.data.portals[] | .services[]?' "$config_path")" # Feed the jq output to the while loop
fi

debug_log "Portal service startup completed"

# Print final report
debug_log "Printing final report"
print_final_report $nas_status

debug_log "System initialization completed with status: $nas_status"
exit $nas_status
