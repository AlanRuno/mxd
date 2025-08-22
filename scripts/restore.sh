#!/bin/bash

set -e

BACKUP_FILE="$1"
RESTORE_PATH="${2:-/opt/mxd/data}"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file> [restore_path]"
    exit 1
fi

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "Restoring from backup: $BACKUP_FILE"
echo "Restore path: $RESTORE_PATH"

./scripts/verify_backup.sh "$BACKUP_FILE"

mkdir -p "$RESTORE_PATH"

if [ -d "$RESTORE_PATH" ] && [ "$(ls -A $RESTORE_PATH)" ]; then
    BACKUP_EXISTING="$RESTORE_PATH.backup.$(date +%Y%m%d_%H%M%S)"
    echo "Backing up existing data to: $BACKUP_EXISTING"
    mv "$RESTORE_PATH" "$BACKUP_EXISTING"
    mkdir -p "$RESTORE_PATH"
fi

echo "Extracting backup..."
if [[ "$BACKUP_FILE" == *.gpg ]]; then
    if [ -z "$MXD_BACKUP_KEY" ]; then
        echo "Error: MXD_BACKUP_KEY environment variable not set for encrypted backup"
        exit 1
    fi
    gpg --batch --yes --passphrase "$MXD_BACKUP_KEY" --decrypt "$BACKUP_FILE" | tar -xzf - -C "$RESTORE_PATH"
else
    tar -xzf "$BACKUP_FILE" -C "$RESTORE_PATH"
fi

chown -R mxdnode:mxdnode "$RESTORE_PATH" 2>/dev/null || true
chmod -R 755 "$RESTORE_PATH"

echo "✓ Restore completed successfully"
echo "Data restored to: $RESTORE_PATH"
