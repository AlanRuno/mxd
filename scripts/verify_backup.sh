#!/bin/bash

set -e

BACKUP_FILE="$1"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup_file>"
    exit 1
fi

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "Verifying backup: $BACKUP_FILE"

CHECKSUM_FILE="$BACKUP_FILE.sha256"
if [ -f "$CHECKSUM_FILE" ]; then
    echo "Verifying checksum..."
    if sha256sum -c "$CHECKSUM_FILE"; then
        echo "✓ Checksum verification passed"
    else
        echo "✗ Checksum verification failed"
        exit 1
    fi
else
    echo "⚠ No checksum file found, skipping checksum verification"
fi

echo "Testing backup extraction..."
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

if [[ "$BACKUP_FILE" == *.gpg ]]; then
    echo "Backup is encrypted, testing decryption..."
    if [ -z "$MXD_BACKUP_KEY" ]; then
        echo "✗ MXD_BACKUP_KEY environment variable not set"
        exit 1
    fi
    gpg --batch --yes --passphrase "$MXD_BACKUP_KEY" --decrypt "$BACKUP_FILE" | tar -tzf - > /dev/null
    echo "✓ Encrypted backup can be decrypted and extracted"
else
    tar -tzf "$BACKUP_FILE" > /dev/null
    echo "✓ Backup can be extracted"
fi

echo "✓ Backup verification completed successfully"
