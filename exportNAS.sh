#!/bin/bash

# Usage: exportNAS.sh [nas|nas_backup]
# Default: nas (primary NAS key). Use nas_backup for backup NAS LUKS.
KEY_NAME="${1:-nas}"
case "$KEY_NAME" in
    nas|nas_backup) ;;
    *)
        echo "ERROR: Invalid key name: $KEY_NAME (use nas or nas_backup)"
        exit 1
        ;;
esac

# Suppress output from exportkey.sh to avoid leaking sensitive information
if ! sudo /vault/keyman/exportkey.sh "$KEY_NAME" >/dev/null 2>&1; then
    # Check specifically for key system initialization error
    if grep -q "ERROR: Key system not initialized" <<< "$(sudo /vault/keyman/exportkey.sh "$KEY_NAME" 2>&1)"; then
        echo "ERROR: Key system not initialized"
        exit 1
    fi
    echo "ERROR: Failed to export NAS key ($KEY_NAME)"
    exit 1
fi

# Read the decrypted key content securely
if ! KEY_CONTENT=$(sudo cat "/mnt/keyexchange/$KEY_NAME" 2>/dev/null); then
    echo "ERROR: Failed to read NAS key file ($KEY_NAME)"
    exit 1
fi

# Extract password from key content
PASSWORD=""
while IFS= read -r line; do
    if [[ "$line" =~ ^password= ]]; then
        PASSWORD=$(echo "$line" | cut -d'=' -f2 | sed 's/^"//;s/"$//')
        break
    fi
done <<< "$KEY_CONTENT"

# Validate password extraction and cleanup on failure
if [ -z "$PASSWORD" ]; then
    echo "ERROR: Failed to extract password from NAS key file"
    exit 1
fi

# Output only the password
echo "$PASSWORD"
exit 0