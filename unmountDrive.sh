#!/bin/bash

# unmountDrive.sh - Specialized script for unmounting drives and closing LUKS containers
# Usage: unmountDrive.sh <device> <mount_point> [mapper_name]
# Example: unmountDrive.sh /dev/sda1 /mnt/nas
# Example: unmountDrive.sh /dev/sdb1 /mnt/nas_backup encrypted_sdb1

# Lock file for preventing concurrent execution
LOCK_FILE="/var/run/unmountDrive.lock"
LOCK_TIMEOUT=30

# Function to log messages to both stdout and syslog
log_message() {
    echo "[DISKMAN] $1"
    logger -t "unmountDrive" "[DISKMAN] $1"
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

# Function to get standardized mapper name (same logic as mountDrive.sh)
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
if [ $# -lt 2 ]; then
    log_message "ERROR: Missing arguments"
    log_message "Usage: unmountDrive.sh <device> <mount_point> [mapper_name]"
    exit 1
fi

DEVICE="$1"
MOUNT_POINT="$2"
MAPPER_NAME="$3"

# Remove trailing slash from mount point if present
MOUNT_POINT="${MOUNT_POINT%/}"

# Ensure device path is correct
if [[ ! "$DEVICE" =~ ^/dev/ ]]; then
    DEVICE="/dev/$DEVICE"
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

# Get standardized mapper name (same logic as mountDrive.sh)
MAPPER_NAME=$(get_standardized_mapper_name "$DEVICE" "$MAPPER_NAME" "$IS_ENCRYPTED")

# If mapper name was generated or provided, treat as encrypted
if [ -n "$MAPPER_NAME" ]; then
    IS_ENCRYPTED=true
    log_message "Using mapper name: $MAPPER_NAME"
    
    if [ -e "/dev/mapper/$MAPPER_NAME" ]; then
        log_message "Mapper device /dev/mapper/$MAPPER_NAME exists"
    else
        log_message "Mapper device /dev/mapper/$MAPPER_NAME does not exist"
    fi
fi

# Check if services already exist and handle them appropriately
if service_exists "$SERVICE_NAME" && service_is_active "$SERVICE_NAME"; then
    log_message "Service $SERVICE_NAME already exists and is active"
    
    # Check if this service was created by init.sh
    if is_init_service "$SERVICE_NAME"; then
        log_message "Service was created by init.sh (boot process) - will be unmounted"
    else
        log_message "Service was created manually - will be unmounted"
    fi
    
    log_message "Stopping existing service before proceeding"
    if ! systemctl stop "$SERVICE_NAME"; then
        log_message "ERROR: Failed to stop existing service $SERVICE_NAME"
        cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
        exit 1
    fi
fi

if service_exists "$MOUNT_UNIT" && service_is_active "$MOUNT_UNIT"; then
    log_message "Mount unit $MOUNT_UNIT already exists and is active"
    log_message "Stopping existing mount unit before proceeding"
    if ! systemctl stop "$MOUNT_UNIT"; then
        log_message "ERROR: Failed to stop existing mount unit $MOUNT_UNIT"
        cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
        exit 1
    fi
fi

# Create a temporary service for unmounting and LUKS closure
if [ "$IS_ENCRYPTED" = true ]; then
    log_message "Creating temporary LUKS unmount service: $SERVICE_NAME"
    cat > "/etc/systemd/system/$SERVICE_NAME" << EOF
[Unit]
Description=Temporary unmount service for $DEVICE
DefaultDependencies=no
Before=umount.target
Conflicts=umount.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/bash -c "echo 'Temporary service for unmounting $DEVICE'"
ExecStop=/usr/bin/bash -c "/vault/scripts/closeNAS.sh $MAPPER_NAME $MOUNT_POINT"

[Install]
WantedBy=multi-user.target
EOF
else
    log_message "Creating temporary unmount service: $SERVICE_NAME"
    cat > "/etc/systemd/system/$SERVICE_NAME" << EOF
[Unit]
Description=Temporary unmount service for $DEVICE
DefaultDependencies=no
Before=umount.target
Conflicts=umount.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/bash -c "echo 'Temporary service for unmounting $DEVICE'"
ExecStop=/usr/bin/bash -c "umount -f $MOUNT_POINT || umount -l $MOUNT_POINT"

[Install]
WantedBy=multi-user.target
EOF
fi

# Reload systemd to pick up new service
log_message "Reloading systemd daemon"
if ! systemctl daemon-reload; then
    log_message "ERROR: Failed to reload systemd daemon"
    cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
    exit 1
fi

# Start the service (no-op)
log_message "Starting temporary service"
if ! systemctl start "$SERVICE_NAME"; then
    log_message "ERROR: Failed to start temporary service"
    cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
    exit 1
fi

# Stop the service (triggers unmount/closure)
log_message "Stopping temporary service (triggering unmount/closure)"
if ! systemctl stop "$SERVICE_NAME"; then
    log_message "ERROR: Failed to stop temporary service"
    cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
    exit 1
fi

# Clean up the service file
log_message "Cleaning up temporary service file"
rm -f "/etc/systemd/system/$SERVICE_NAME"
if ! systemctl daemon-reload; then
    log_message "ERROR: Failed to reload systemd daemon after cleanup"
    exit 1
fi

# Verify the unmount/closure was successful
if [ "$IS_ENCRYPTED" = true ]; then
    if [ -e "/dev/mapper/$MAPPER_NAME" ]; then
        log_message "ERROR: LUKS container closure failed - mapper still exists"
        cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
        exit 1
    fi
    log_message "Successfully closed LUKS container: $MAPPER_NAME"
else
    if mountpoint -q "$MOUNT_POINT"; then
        log_message "ERROR: Unmount failed - mount point still active"
        cleanup_partial_failure "$SERVICE_NAME" "$MOUNT_UNIT" "$MOUNT_POINT" "$MAPPER_NAME"
        exit 1
    fi
    log_message "Successfully unmounted: $MOUNT_POINT"
fi

exit 0 