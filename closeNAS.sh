#!/bin/bash

# closeNAS.sh - Helper script to forcibly unmount and close LUKS containers
# Usage: closeNAS.sh <mapper_name> <mount_point>

# Function to log messages to both stdout and syslog
log_message() {
    echo "[DISKMAN] $1"
    logger -t "closeNAS" "[DISKMAN] $1"
}

# Check if arguments are provided
if [ $# -lt 1 ]; then
    log_message "ERROR: Missing arguments"
    log_message "Usage: closeNAS.sh <mapper_name> [mount_point]"
    exit 1
fi

MAPPER_NAME="$1"
MOUNT_POINT="$2"

log_message "Starting forced unmount and LUKS container closure for $MAPPER_NAME"

# Step 1: Unmount the device if a mount point was provided
if [ -n "$MOUNT_POINT" ] && mountpoint -q "$MOUNT_POINT"; then
    log_message "Unmounting $MOUNT_POINT"
    
    # Try standard unmount first
    if ! umount "$MOUNT_POINT" 2>/dev/null; then
        log_message "Standard unmount failed, trying lazy unmount"
        # Try lazy unmount
        if ! umount -l "$MOUNT_POINT" 2>/dev/null; then
            log_message "Lazy unmount failed, trying force unmount"
            # Try force unmount
            if ! umount -f "$MOUNT_POINT" 2>/dev/null; then
                log_message "Force unmount failed, killing processes using $MOUNT_POINT"
                # Kill any processes using the mount point
                fuser -km "$MOUNT_POINT" 2>/dev/null
                sleep 1
                umount -f "$MOUNT_POINT" 2>/dev/null
            fi
        fi
    fi
    
    # Verify unmount was successful
    if mountpoint -q "$MOUNT_POINT"; then
        log_message "ERROR: Failed to unmount $MOUNT_POINT"
    else
        log_message "Successfully unmounted $MOUNT_POINT"
    fi
fi

# Step 2: Make sure no processes are using the mapper device
log_message "Killing processes using /dev/mapper/$MAPPER_NAME"
fuser -km "/dev/mapper/$MAPPER_NAME" 2>/dev/null

# Step 3: Drop caches to help release the device
log_message "Dropping caches"
sync
echo 3 > /proc/sys/vm/drop_caches

# Step 4: Try to close the LUKS container
log_message "Attempting to close LUKS container $MAPPER_NAME"
if ! cryptsetup close "$MAPPER_NAME" 2>/dev/null; then
    log_message "Standard close failed, trying force close"
    # Try force close
    if ! cryptsetup close --force "$MAPPER_NAME" 2>/dev/null; then
        log_message "Force close failed, trying direct device mapper removal"
        # Try direct device mapper removal
        if ! dmsetup remove --force "$MAPPER_NAME" 2>/dev/null; then
            log_message "ERROR: Failed to close LUKS container $MAPPER_NAME"
            exit 1
        fi
    fi
fi

# Step 5: Verify the closure
if [ -e "/dev/mapper/$MAPPER_NAME" ]; then
    log_message "ERROR: Device /dev/mapper/$MAPPER_NAME still exists"
    exit 1
else
    log_message "Successfully closed LUKS container $MAPPER_NAME"
    exit 0
fi 