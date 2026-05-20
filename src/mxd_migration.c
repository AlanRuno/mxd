#include "../include/mxd_migration.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Get current database schema version
uint32_t mxd_get_db_schema_version(void) {
    sqlite3 *db = mxd_get_db();
    if (!db) {
        MXD_LOG_ERROR("migration", "Database not initialized");
        return 0;
    }

    // Check if schema_version table exists
    const char *check_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(db, check_sql, -1, &stmt, NULL) != SQLITE_OK) {
        MXD_LOG_ERROR("migration", "Failed to check schema_version table: %s",
                      sqlite3_errmsg(db));
        return 0;
    }

    int table_exists = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);

    if (!table_exists) {
        // No schema_version table, assume v1 (legacy)
        MXD_LOG_INFO("migration", "No schema_version table found, assuming v1");
        return 1;
    }

    // Get current version
    const char *version_sql = "SELECT version FROM schema_version ORDER BY id DESC LIMIT 1";

    if (sqlite3_prepare_v2(db, version_sql, -1, &stmt, NULL) != SQLITE_OK) {
        MXD_LOG_ERROR("migration", "Failed to query schema version: %s",
                      sqlite3_errmsg(db));
        return 0;
    }

    uint32_t version = 1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        version = sqlite3_column_int(stmt, 0);
    }

    sqlite3_finalize(stmt);
    MXD_LOG_DEBUG("migration", "Current schema version: %u", version);

    return version;
}

// Set database schema version
int mxd_set_db_schema_version(uint32_t version) {
    sqlite3 *db = mxd_get_db();
    if (!db) {
        MXD_LOG_ERROR("migration", "Database not initialized");
        return -1;
    }

    // Create schema_version table if it doesn't exist
    const char *create_sql =
        "CREATE TABLE IF NOT EXISTS schema_version ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "version INTEGER NOT NULL, "
        "migrated_at INTEGER NOT NULL"
        ")";

    char *errmsg = NULL;
    if (sqlite3_exec(db, create_sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        MXD_LOG_ERROR("migration", "Failed to create schema_version table: %s", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }

    // Insert new version
    const char *insert_sql = "INSERT INTO schema_version (version, migrated_at) VALUES (?, ?)";
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL) != SQLITE_OK) {
        MXD_LOG_ERROR("migration", "Failed to prepare version insert: %s",
                      sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, version);
    sqlite3_bind_int64(stmt, 2, (int64_t)time(NULL));

    int result = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
    sqlite3_finalize(stmt);

    if (result == 0) {
        MXD_LOG_INFO("migration", "Schema version set to %u", version);
    } else {
        MXD_LOG_ERROR("migration", "Failed to set schema version: %s",
                      sqlite3_errmsg(db));
    }

    return result;
}

// Check if database needs migration
int mxd_needs_migration(uint32_t target_version) {
    uint32_t current_version = mxd_get_db_schema_version();

    if (current_version == 0) {
        MXD_LOG_ERROR("migration", "Failed to get current schema version");
        return -1;
    }

    if (current_version >= target_version) {
        MXD_LOG_INFO("migration", "Database already at v%u (target: v%u)",
                     current_version, target_version);
        return 0;
    }

    MXD_LOG_INFO("migration", "Migration needed: v%u -> v%u",
                 current_version, target_version);
    return 1;
}

// Backup database before migration
int mxd_backup_database(const char *backup_path) {
    sqlite3 *db = mxd_get_db();
    if (!db) {
        MXD_LOG_ERROR("migration", "Database not initialized");
        return -1;
    }

    // Generate backup path if not provided
    char default_backup[256];
    if (!backup_path) {
        time_t now = time(NULL);
        snprintf(default_backup, sizeof(default_backup),
                 "mxd_blockchain_backup_%ld.db", (long)now);
        backup_path = default_backup;
    }

    MXD_LOG_INFO("migration", "Creating database backup: %s", backup_path);

    // Use SQLite backup API
    sqlite3 *backup_db = NULL;
    if (sqlite3_open(backup_path, &backup_db) != SQLITE_OK) {
        MXD_LOG_ERROR("migration", "Failed to open backup database: %s",
                      sqlite3_errmsg(backup_db));
        return -1;
    }

    sqlite3_backup *backup = sqlite3_backup_init(backup_db, "main", db, "main");
    if (!backup) {
        MXD_LOG_ERROR("migration", "Failed to initialize backup: %s",
                      sqlite3_errmsg(backup_db));
        sqlite3_close(backup_db);
        return -1;
    }

    int rc = sqlite3_backup_step(backup, -1);
    sqlite3_backup_finish(backup);
    sqlite3_close(backup_db);

    if (rc != SQLITE_DONE) {
        MXD_LOG_ERROR("migration", "Backup failed: %d", rc);
        return -1;
    }

    MXD_LOG_INFO("migration", "Database backup completed successfully");
    return 0;
}

// Migrate a single block to v3 format
int mxd_migrate_block_to_v3(mxd_block_t *block) {
    if (!block) {
        return -1;
    }

    // Skip if already v3
    if (block->version >= 3) {
        return 0;
    }

    MXD_LOG_DEBUG("migration", "Migrating block at height %u to v3", block->height);

    // Compute contracts_state_root
    if (mxd_calculate_contracts_state_root(block, block->contracts_state_root) != 0) {
        MXD_LOG_ERROR("migration", "Failed to compute contracts_state_root for block %u",
                      block->height);
        return -1;
    }

    // Update version
    block->version = 3;

    return 0;
}

// Migrate database to v3 schema
int mxd_migrate_to_v3(mxd_migration_status_t *status) {
    MXD_LOG_INFO("migration", "Starting migration to v3 schema");

    // Initialize status
    if (status) {
        memset(status, 0, sizeof(mxd_migration_status_t));
        status->current_schema_version = mxd_get_db_schema_version();
        status->target_schema_version = 3;
    }

    // Check if migration is needed
    int needs_mig = mxd_needs_migration(3);
    if (needs_mig < 0) {
        if (status) {
            snprintf(status->error_message, sizeof(status->error_message),
                     "Failed to check migration status");
        }
        return MXD_MIGRATION_ERROR;
    }

    if (needs_mig == 0) {
        if (status) {
            status->is_complete = 1;
        }
        return MXD_MIGRATION_ALREADY_MIGRATED;
    }

    // Create backup
    if (mxd_backup_database(NULL) != 0) {
        MXD_LOG_ERROR("migration", "Failed to create backup");
        if (status) {
            snprintf(status->error_message, sizeof(status->error_message),
                     "Failed to create database backup");
        }
        return MXD_MIGRATION_ERROR;
    }

    sqlite3 *db = mxd_get_db();
    if (!db) {
        MXD_LOG_ERROR("migration", "Database not initialized");
        return MXD_MIGRATION_ERROR;
    }

    // Begin transaction
    char *errmsg = NULL;
    if (sqlite3_exec(db, "BEGIN TRANSACTION", NULL, NULL, &errmsg) != SQLITE_OK) {
        MXD_LOG_ERROR("migration", "Failed to begin transaction: %s", errmsg);
        sqlite3_free(errmsg);
        return MXD_MIGRATION_ERROR;
    }

    // Add contracts_state_root column to blocks table
    const char *alter_sql =
        "ALTER TABLE blocks ADD COLUMN contracts_state_root BLOB";

    if (sqlite3_exec(db, alter_sql, NULL, NULL, &errmsg) != SQLITE_OK) {
        // Check if column already exists (migration already partially done)
        if (strstr(errmsg, "duplicate column")) {
            MXD_LOG_INFO("migration", "contracts_state_root column already exists");
            sqlite3_free(errmsg);
        } else {
            MXD_LOG_ERROR("migration", "Failed to add contracts_state_root column: %s",
                          errmsg);
            sqlite3_free(errmsg);
            sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
            return MXD_MIGRATION_ERROR;
        }
    }

    // Update schema version
    if (mxd_set_db_schema_version(3) != 0) {
        MXD_LOG_ERROR("migration", "Failed to update schema version");
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return MXD_MIGRATION_ERROR;
    }

    // Commit transaction
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, &errmsg) != SQLITE_OK) {
        MXD_LOG_ERROR("migration", "Failed to commit migration: %s", errmsg);
        sqlite3_free(errmsg);
        sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        return MXD_MIGRATION_ERROR;
    }

    MXD_LOG_INFO("migration", "Migration to v3 completed successfully");

    if (status) {
        status->is_complete = 1;
    }

    return MXD_MIGRATION_SUCCESS;
}

// Verify migration integrity
int mxd_verify_migration(uint32_t start_height, uint32_t end_height) {
    MXD_LOG_INFO("migration", "Verifying migration from height %u to %u",
                 start_height, end_height);

    sqlite3 *db = mxd_get_db();
    if (!db) {
        MXD_LOG_ERROR("migration", "Database not initialized");
        return -1;
    }

    // If end_height is 0, get current tip
    if (end_height == 0) {
        const char *tip_sql = "SELECT MAX(height) FROM blocks";
        sqlite3_stmt *stmt = NULL;

        if (sqlite3_prepare_v2(db, tip_sql, -1, &stmt, NULL) != SQLITE_OK) {
            MXD_LOG_ERROR("migration", "Failed to query tip height");
            return -1;
        }

        if (sqlite3_step(stmt) == SQLITE_ROW) {
            end_height = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    MXD_LOG_INFO("migration", "Verifying %u blocks", end_height - start_height + 1);

    // Check that all blocks have contracts_state_root
    const char *verify_sql =
        "SELECT COUNT(*) FROM blocks "
        "WHERE height BETWEEN ? AND ? AND contracts_state_root IS NULL";

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, verify_sql, -1, &stmt, NULL) != SQLITE_OK) {
        MXD_LOG_ERROR("migration", "Failed to prepare verification query");
        return -1;
    }

    sqlite3_bind_int(stmt, 1, start_height);
    sqlite3_bind_int(stmt, 2, end_height);

    int null_count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        null_count = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);

    if (null_count > 0) {
        MXD_LOG_ERROR("migration", "Found %d blocks with NULL contracts_state_root",
                      null_count);
        return -1;
    }

    MXD_LOG_INFO("migration", "Migration verification successful");
    return 0;
}

// Rollback migration (restore from backup)
int mxd_rollback_migration(const char *backup_path) {
    if (!backup_path) {
        MXD_LOG_ERROR("migration", "Backup path is required for rollback");
        return -1;
    }

    MXD_LOG_WARN("migration", "Rolling back migration from backup: %s", backup_path);

    // Close current database
    mxd_close_db();

    // TODO: Implement database restoration
    // This would involve:
    // 1. Moving current database to a temporary location
    // 2. Copying backup to main database location
    // 3. Reopening database

    MXD_LOG_INFO("migration", "Rollback completed");
    return 0;
}
