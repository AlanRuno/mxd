#ifndef MXD_MIGRATION_H
#define MXD_MIGRATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "mxd_blockchain.h"

/**
 * MXD Database Migration Utilities
 *
 * Handles upgrading blockchain database schema and data structures
 * when protocol versions change.
 */

// Migration result codes
#define MXD_MIGRATION_SUCCESS 0
#define MXD_MIGRATION_ERROR -1
#define MXD_MIGRATION_ALREADY_MIGRATED -2
#define MXD_MIGRATION_INCOMPATIBLE -3

/**
 * Migration status structure
 */
typedef struct {
    uint32_t current_schema_version;
    uint32_t target_schema_version;
    uint32_t blocks_migrated;
    uint32_t total_blocks;
    int is_complete;
    char error_message[256];
} mxd_migration_status_t;

/**
 * Get current database schema version
 *
 * @return Schema version (1, 2, or 3)
 */
uint32_t mxd_get_db_schema_version(void);

/**
 * Set database schema version
 *
 * @param version Schema version to set
 * @return 0 on success, -1 on error
 */
int mxd_set_db_schema_version(uint32_t version);

/**
 * Check if database needs migration
 *
 * @param target_version Target schema version
 * @return 1 if migration needed, 0 if not, -1 on error
 */
int mxd_needs_migration(uint32_t target_version);

/**
 * Migrate database to v3 schema
 *
 * This adds the contracts_state_root column to blocks table
 * and computes state roots for all existing blocks.
 *
 * @param status Optional status structure to track progress
 * @return 0 on success, negative on error
 */
int mxd_migrate_to_v3(mxd_migration_status_t *status);

/**
 * Migrate a single block to v3 format
 *
 * Computes contracts_state_root for the block
 *
 * @param block Block to migrate (will be modified in place)
 * @return 0 on success, -1 on error
 */
int mxd_migrate_block_to_v3(mxd_block_t *block);

/**
 * Backup database before migration
 *
 * Creates a backup copy of the blockchain database
 *
 * @param backup_path Path to save backup (NULL for default)
 * @return 0 on success, -1 on error
 */
int mxd_backup_database(const char *backup_path);

/**
 * Verify migration integrity
 *
 * Checks that all blocks have valid state roots after migration
 *
 * @param start_height Starting block height to verify
 * @param end_height Ending block height to verify (0 for tip)
 * @return 0 if valid, -1 on error
 */
int mxd_verify_migration(uint32_t start_height, uint32_t end_height);

/**
 * Rollback migration (restore from backup)
 *
 * @param backup_path Path to backup file
 * @return 0 on success, -1 on error
 */
int mxd_rollback_migration(const char *backup_path);

#ifdef __cplusplus
}
#endif

#endif // MXD_MIGRATION_H
