#ifndef MXD_BACKUP_H
#define MXD_BACKUP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char backup_dir[256];
    uint32_t retention_days;
    int enable_compression;
    int enable_encryption;
    uint32_t backup_interval_hours;
} mxd_backup_config_t;

typedef struct {
    char backup_path[512];
    uint64_t backup_size;
    uint64_t timestamp;
    uint32_t blockchain_height;
    char checksum[65];
    int is_valid;
} mxd_backup_info_t;

int mxd_init_backup_system(const mxd_backup_config_t *config);
void mxd_cleanup_backup_system(void);

int mxd_create_blockchain_backup(const char *db_path, mxd_backup_info_t *backup_info);
int mxd_restore_blockchain_backup(const char *backup_path, const char *restore_path);
int mxd_verify_backup_integrity(const char *backup_path);

int mxd_list_available_backups(mxd_backup_info_t *backups, size_t *backup_count);
int mxd_cleanup_old_backups(void);

int mxd_create_config_backup(const char *config_path);
int mxd_restore_config_backup(const char *backup_path, const char *restore_path);

#ifdef __cplusplus
}
#endif

#endif // MXD_BACKUP_H
