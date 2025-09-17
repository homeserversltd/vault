#!/bin/bash

# mountDrive.sh - Helper script to mount drives using systemd services
# Usage: mountDrive.sh <action> <device> <mount_point> [mapper_name]
# Example: mountDrive.sh mount sda1 /mnt/nas
# Example: mountDrive.sh mount sdb1 /mnt/nas_backup encrypted_sdb1
# Example: mountDrive.sh unmount sda1 /mnt/nas
# Example: mountDrive.sh unmount sdb1 /mnt/nas_backup encrypted_sdb1

# Lock file for preventing concurrent execution
LOCK_FILE="/var/run/mountDrive.lock"
LOCK_TIMEOUT=30

# Function to log messages to both stdout and syslog
log_message() {
    echo "[DISKMAN] $1"
    logger -t "mountDrive" "[DISKMAN] $1"
}

# Function to acquire lock
acquire_lock() {
    local lock_acquired=false
    local attempts=0
    
    while [ $attempts -lt $LOCK_TIMEOUT ]; do
        if (set -C; echo $$ > "$LOCK_FILE") 2>/dev/null; then
            lock_acquired=true
            break
        fi
        
        # Check if lock is stale (process no longer exists)
        if [ -f "$LOCK_FILE" ]; then
            local lock_pid=$(cat "$LOCK_FILE" 2>/dev/null)
            if [ -n "$lock_pid" ] && ! kill -0 "$lock_pid" 2>/dev/null; then
                log_message "Removing stale lock file (PID $lock_pid no longer exists)"
                rm -f "$LOCK_FILE"
                continue
            fi
        fi
        
        attempts=$((attempts + 1))
        sleep 1
    done
    
    if [ "$lock_acquired" = false ]; then
        log_message "ERROR: Failed to acquire lock after $LOCK_TIMEOUT seconds"
        exit 1
    fi
    
    log_message "Acquired lock (PID: $$)"
}

# Function to release lock
release_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local lock_pid=$(cat "$LOCK_FILE" 2>/dev/null)
        if [ "$lock_pid" = "$$" ]; then
            rm -f "$LOCK_FILE"
            log_message "Released lock"
        else
            log_message "WARNING: Lock file contains different PID ($lock_pid), not releasing"
        fi
    fi
}

# Function to cleanup on exit
cleanup_on_exit() {
    local exit_code=$?
    release_lock
    exit $exit_code
}

# Set up cleanup trap
trap cleanup_on_exit EXIT INT TERM

# Function to check if service exists and is active
service_exists() {
    local service_name="$1"
    systemctl list-unit-files | grep -q "^${service_name}\s"
}

service_is_active() {
    local service_name="$1"
    systemctl is-active "$service_name" >/dev/null 2>&1
}

# Function to get standardized mapper name
get_standardized_mapper_name() {
    local device="$1"
    local provided_mapper="$2"
    local is_luks="$3"
    
    # If mapper is explicitly provided, use it
    if [ -n "$provided_mapper" ]; then
        echo "$provided_mapper"
        return
    fi
    
    # If device is LUKS encrypted, generate standard mapper name
    if [ "$is_luks" = true ]; then
        echo "$(basename "$device")_crypt"
        return
    fi
    
    # No mapper for non-encrypted devices
    echo ""
}

# Function to check if a service was created by init.sh
is_init_service() {
    local service_name="$1"
    
    # Check if service file contains init.sh references
    if [ -f "/etc/systemd/system/$service_name" ]; then
        if grep -q "init.sh\|exportNAS.sh" "/etc/systemd/system/$service_name" 2>/dev/null; then
            return 0  # True - created by init
        fi
    fi
    
    return 1  # False - created manually
}

# Function to cleanup partial failure state
cleanup_partial_failure() {
    local service_name="$1"
    local mount_unit="$2"
    local mount_point="$3"
    local mapper_name="$4"
    
    log_message "Cleaning up partial failure state"
    
    # Stop services if they exist and are active
    if service_exists "$service_name" && service_is_active "$service_name"; then
        log_message "Stopping service: $service_name"
        systemctl stop "$service_name" 2>/dev/null || true
    fi
    
    if service_exists "$mount_unit" && service_is_active "$mount_unit"; then
        log_message "Stopping mount unit: $mount_unit"
        systemctl stop "$mount_unit" 2>/dev/null || true
    fi
    
    # Force unmount if still mounted
    if [ -n "$mount_point" ] && mountpoint -q "$mount_point" 2>/dev/null; then
        log_message "Force unmounting: $mount_point"
        umount -f "$mount_point" 2>/dev/null || umount -l "$mount_point" 2>/dev/null || true
    fi
    
    # Close LUKS container if mapper exists
    if [ -n "$mapper_name" ] && [ -e "/dev/mapper/$mapper_name" ]; then
        log_message "Closing LUKS container: $mapper_name"
        cryptsetup close "$mapper_name" 2>/dev/null || cryptsetup close --force "$mapper_name" 2>/dev/null || true
    fi
    
    # Remove service files
    rm -f "/etc/systemd/system/$service_name"
    rm -f "/etc/systemd/system/$mount_unit"
    
    # Reload systemd
    systemctl daemon-reload 2>/dev/null || true
}

# Acquire lock to prevent concurrent execution
acquire_lock

# Check if arguments are provided
if [ $# -lt 3 ]; then
    log_message "ERROR: Missing arguments"
    log_message "Usage: mountDrive.sh <action> <device> <mount_point> [mapper_name]"
    exit 1
fi

ACTION="$1"
DEVICE="$2"
MOUNT_POINT="$3"
MAPPER_NAME="$4"

# Remove trailing slash from mount point if present
MOUNT_POINT="${MOUNT_POINT%/}"

# Ensure device path is correct
if [[ ! "$DEVICE" =~ ^/dev/ ]]; then
    DEVICE="/dev/$DEVICE"
fi

# Verify device exists
if [ ! -e "$DEVICE" ]; then
    log_message "ERROR: Device $DEVICE does not exist"
    exit 1
fi

# Convert mount point to systemd unit name
MOUNT_UNIT=$(systemd-escape --path "${MOUNT_POINT}").mount
SERVICE_NAME="$(basename "$DEVICE").service"

# Check if device is encrypted
IS_ENCRYPTED=false
if cryptsetup isLuks "$DEVICE" 2>/dev/null; then
    IS_ENCRYPTED=true
    log_message "Device $DEVICE is LUKS encrypted"
fi

# Get standardized mapper name
MAPPER_NAME=$(get_standardized_mapper_name "$DEVICE" "$MAPPER_NAME" "$IS_ENCRYPTED")

# If mapper name was generated or provided, treat as encrypted
if [ -n "$MAPPER_NAME" ]; then
    IS_ENCRYPTED=true
    log_message "Using mapper name: $MAPPER_NAME"
    
    # Check if mapper exists
    if [ -e "/dev/mapper/$MAPPER_NAME" ]; then
        log_message "Mapper device /dev/mapper/$MAPPER_NAME exists"
        MAPPER_ALREADY_EXISTS=true
    else
        log_message "Mapper device /dev/mapper/$MAPPER_NAME does not exist"
        MAPPER_ALREADY_EXISTS=false
    fi
fi

# Get filesystem type
if [ "$IS_ENCRYPTED" = true ] && [ "$ACTION" = "mount" ]; then
    # For encrypted devices, we need to check the mapper device
    FILESYSTEM="auto"
    log_message "Using auto filesystem type for encrypted device"
else
    log_message "Checking filesystem type for $DEVICE"
    FILESYSTEM=$(blkid -o value -s TYPE "$DEVICE" 2>/dev/null || echo "auto")
    log_message "Detected filesystem: $FILESYSTEM"
fi

case "${ACTION}" in
    mount)
        log_message "Mounting $DEVICE to $MOUNT_POINT"
        
        # Check if services already exist and handle them intelligently
        if service_exists "$SERVICE_NAME" && service_is_active "$SERVICE_NAME"; then
            log_message "Service $SERVICE_NAME already exists and is active"
            
            # Check if this service was created by init.sh
            if is_init_service "$SERVICE_NAME"; then
                log_message "Service was created by init.sh (boot process)"
            else
                log_message "Service was created manually"
            fi
            
            # Check if this is the same device and mount point
            local existing_mount=$(findmnt -n -o TARGET "/dev/mapper/$MAPPER_NAME" 2>/dev/null || findmnt -n -o TARGET "$DEVICE" 2>/dev/null)
            if [ "$existing_mount" = "$MOUNT_POINT" ]; then
                log_message "Device $DEVICE is already mounted at $MOUNT_POINT - no action needed"
                exit 0
            else
                log_message "Device $DEVICE is mounted elsewhere ($existing_mount), stopping existing service"
                if ! systemctl stop "$SERVICE_NAME"; then
                    log_message "ERROR: Failed to stop existing service $SERVICE_NAME"
                    cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
                    exit 1
                fi
            fi
        fi
        
        if service_exists "$MOUNT_UNIT" && service_is_active "$MOUNT_UNIT"; then
            log_message "Mount unit $MOUNT_UNIT already exists and is active"
            
            # Check if this is the same mount point
            if mountpoint -q "$MOUNT_POINT"; then
                log_message "Mount point $MOUNT_POINT is already active - no action needed"
                exit 0
            else
                log_message "Mount unit exists but mount point is different, stopping existing unit"
                if ! systemctl stop "$MOUNT_UNIT"; then
                    log_message "ERROR: Failed to stop existing mount unit $MOUNT_UNIT"
                    cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
                    exit 1
                fi
            fi
        fi
        
        # Create mount directory if it doesn't exist
        if [ ! -d "$MOUNT_POINT" ]; then
            log_message "Creating mount point directory: $MOUNT_POINT"
            if ! mkdir -p "$MOUNT_POINT"; then
                log_message "ERROR: Failed to create mount point directory: $MOUNT_POINT"
                exit 1
            fi
        fi
        
        if [ "$IS_ENCRYPTED" = true ]; then
            # Handle encrypted drive
            log_message "Setting up encrypted drive with mapper: $MAPPER_NAME"
            
            # Verify we can access the NAS key - only needed if mapper doesn't exist
            if [ "$MAPPER_ALREADY_EXISTS" = false ]; then
                log_message "Verifying NAS key access"
                NAS_KEY_OUTPUT=$(/vault/scripts/exportNAS.sh 2>&1)
                if [ $? -ne 0 ]; then
                    log_message "ERROR: Failed to access NAS key: $NAS_KEY_OUTPUT"
                    cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
                    exit 1
                fi
            fi
            
            # Create systemd service for LUKS container
            log_message "Creating systemd service for LUKS container: $SERVICE_NAME"
            
            # If mapper already exists, the ExecStart should be a no-op success
            if [ "$MAPPER_ALREADY_EXISTS" = true ]; then
                cat > "/etc/systemd/system/$SERVICE_NAME" << EOF
[Unit]
Description=LUKS container for $DEVICE
DefaultDependencies=no
Before=${MOUNT_UNIT}
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/bash -c "echo 'Mapper device $MAPPER_NAME already exists, skipping LUKS open'"
ExecStop=/usr/bin/bash -c "/vault/scripts/closeNAS.sh $MAPPER_NAME $MOUNT_POINT"

[Install]
WantedBy=multi-user.target
EOF
            else
                cat > "/etc/systemd/system/$SERVICE_NAME" << EOF
[Unit]
Description=LUKS container for $DEVICE
DefaultDependencies=no
Before=${MOUNT_UNIT}
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/bash -c "/vault/scripts/exportNAS.sh | /usr/sbin/cryptsetup luksOpen $DEVICE $MAPPER_NAME"
ExecStop=/usr/bin/bash -c "/vault/scripts/closeNAS.sh $MAPPER_NAME $MOUNT_POINT"

[Install]
WantedBy=multi-user.target
EOF
            fi

            # Create mount unit for encrypted drive
            log_message "Creating mount unit: $MOUNT_UNIT"
            cat > "/etc/systemd/system/$MOUNT_UNIT" << EOF
[Unit]
Description=Mount for $MAPPER_NAME
Requires=$SERVICE_NAME
After=$SERVICE_NAME

[Mount]
What=/dev/mapper/$MAPPER_NAME
Where=$MOUNT_POINT
Type=$FILESYSTEM
Options=defaults

[Install]
WantedBy=multi-user.target
EOF

            # Start the units
            log_message "Reloading systemd daemon"
            if ! systemctl daemon-reload; then
                log_message "ERROR: Failed to reload systemd daemon"
                cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
                exit 1
            fi
            
            log_message "Starting LUKS service: $SERVICE_NAME"
            if ! systemctl start "$SERVICE_NAME"; then
                log_message "ERROR: Failed to start LUKS service"
                cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
                exit 1
            fi
            
            log_message "Starting mount unit: $MOUNT_UNIT"
            if ! systemctl start "$MOUNT_UNIT"; then
                log_message "ERROR: Failed to mount encrypted drive"
                cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
                exit 1
            fi
            
            log_message "Successfully mounted encrypted drive $DEVICE to $MOUNT_POINT"
            
        else
            # Handle non-encrypted drive
            log_message "Creating mount unit for non-encrypted drive: $MOUNT_UNIT"
            cat > "/etc/systemd/system/$MOUNT_UNIT" << EOF
[Unit]
Description=Mount for $DEVICE
After=local-fs.target

[Mount]
What=$DEVICE
Where=$MOUNT_POINT
Type=$FILESYSTEM
Options=defaults

[Install]
WantedBy=multi-user.target
EOF

            # Start the unit
            log_message "Reloading systemd daemon"
            if ! systemctl daemon-reload; then
                log_message "ERROR: Failed to reload systemd daemon"
                cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
                exit 1
            fi
            
            log_message "Starting mount unit: $MOUNT_UNIT"
            if ! systemctl start "$MOUNT_UNIT"; then
                log_message "ERROR: Failed to mount drive"
                cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
                exit 1
            fi
            
            log_message "Successfully mounted drive $DEVICE to $MOUNT_POINT"
        fi
        ;;
        
    unmount)
        log_message "Unmounting $DEVICE from $MOUNT_POINT"
        
        # Check if services exist before trying to stop them
        local mount_unit_stopped=false
        local service_stopped=false
        
        if service_exists "$MOUNT_UNIT" && service_is_active "$MOUNT_UNIT"; then
            log_message "Stopping mount unit: $MOUNT_UNIT"
            if systemctl stop "$MOUNT_UNIT"; then
                mount_unit_stopped=true
                log_message "Successfully stopped mount unit: $MOUNT_UNIT"
            else
                log_message "ERROR: Failed to stop mount unit: $MOUNT_UNIT"
                cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
                exit 1
            fi
        else
            log_message "Mount unit $MOUNT_UNIT does not exist or is not active"
            mount_unit_stopped=true
        fi
        
        if [ "$IS_ENCRYPTED" = true ]; then
            if service_exists "$SERVICE_NAME" && service_is_active "$SERVICE_NAME"; then
                log_message "Stopping LUKS service: $SERVICE_NAME"
                if systemctl stop "$SERVICE_NAME"; then
                    service_stopped=true
                    log_message "Successfully stopped LUKS service: $SERVICE_NAME"
                else
                    log_message "ERROR: Failed to stop LUKS service: $SERVICE_NAME"
                    cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
                    exit 1
                fi
            else
                log_message "LUKS service $SERVICE_NAME does not exist or is not active"
                service_stopped=true
            fi
        else
            service_stopped=true
        fi
        
        # Clean up the unit files
        log_message "Removing systemd service files"
        rm -f "/etc/systemd/system/$SERVICE_NAME"
        rm -f "/etc/systemd/system/$MOUNT_UNIT"
        
        # Reload systemd
        log_message "Reloading systemd daemon"
        if ! systemctl daemon-reload; then
            log_message "ERROR: Failed to reload systemd daemon"
            exit 1
        fi
        
        log_message "Successfully unmounted $DEVICE from $MOUNT_POINT"
        ;;
        
    *)
        log_message "ERROR: Unknown action: $ACTION"
        log_message "Valid actions are: mount, unmount"
        exit 1
        ;;
esac

exit 0 