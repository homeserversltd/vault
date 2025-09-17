#!/bin/bash

# Suppress output from exportkey.sh to avoid leaking sensitive information
if ! sudo /vault/keyman/exportkey.sh nas >/dev/null 2>&1; then
    # Check specifically for key system initialization error
    if grep -q "ERROR: Key system not initialized" <<< "$(sudo /vault/keyman/exportkey.sh nas 2>&1)"; then
        echo "ERROR: Key system not initialized"
        exit 1
    fi
    echo "ERROR: Failed to export NAS key"
    exit 1
fi

# Read the decrypted key content securely
if ! KEY_CONTENT=$(sudo cat /mnt/keyexchange/nas 2>/dev/null); then
    echo "ERROR: Failed to read NAS key file"
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