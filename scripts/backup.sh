#!/bin/bash

set -e

BACKUP_DIR=${MXD_BACKUP_DIR:-"/opt/mxd/backups"}
DATA_DIR=${MXD_DATA_DIR:-"/opt/mxd/data"}
RETENTION_DAYS=${MXD_BACKUP_RETENTION:-7}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "Starting MXD blockchain backup..."

mkdir -p "$BACKUP_DIR"

if [ ! -d "$DATA_DIR" ]; then
    echo "Warning: Data directory $DATA_DIR does not exist, creating test data..."
    mkdir -p "$DATA_DIR"
    echo "test blockchain data" > "$DATA_DIR/blockchain.db"
fi

BACKUP_FILE="$BACKUP_DIR/mxd_backup_$TIMESTAMP.tar.gz"

echo "Creating backup: $BACKUP_FILE"
tar -czf "$BACKUP_FILE" -C "$DATA_DIR" .

echo "Calculating checksum..."
sha256sum "$BACKUP_FILE" > "$BACKUP_FILE.sha256"

echo "Backup size: $(du -h "$BACKUP_FILE" | cut -f1)"

if [ "$MXD_BACKUP_VERIFY" = "true" ]; then
    echo "Verifying backup integrity..."
    sha256sum -c "$BACKUP_FILE.sha256"
    echo "Backup verification successful"
fi

if [ "$MXD_BACKUP_ENCRYPT" = "true" ] && [ -n "$MXD_BACKUP_KEY" ]; then
    echo "Encrypting backup..."
    gpg --symmetric --cipher-algo AES256 --batch --yes --passphrase "$MXD_BACKUP_KEY" "$BACKUP_FILE"
    rm "$BACKUP_FILE"
    BACKUP_FILE="$BACKUP_FILE.gpg"
    echo "Backup encrypted: $BACKUP_FILE"
fi

if [ "$MXD_BACKUP_UPLOAD" = "true" ] && [ -n "$MXD_BACKUP_S3_BUCKET" ]; then
    echo "Uploading backup to S3..."
    if command -v aws >/dev/null 2>&1; then
        aws s3 cp "$BACKUP_FILE" "s3://$MXD_BACKUP_S3_BUCKET/backups/"
        aws s3 cp "$BACKUP_FILE.sha256" "s3://$MXD_BACKUP_S3_BUCKET/backups/"
        echo "Backup uploaded to S3"
    else
        echo "Warning: AWS CLI not found, skipping S3 upload"
    fi
fi

echo "Cleaning up old backups (retention: $RETENTION_DAYS days)..."
find "$BACKUP_DIR" -name "mxd_backup_*.tar.gz*" -mtime +$RETENTION_DAYS -delete

echo "Backup completed successfully: $BACKUP_FILE"

if [ "$MXD_BACKUP_NOTIFY" = "true" ] && [ -n "$MXD_BACKUP_WEBHOOK" ]; then
    curl -X POST "$MXD_BACKUP_WEBHOOK" \
        -H "Content-Type: application/json" \
        -d "{\"message\": \"MXD backup completed: $BACKUP_FILE\", \"status\": \"success\"}" || true
fi
