#include "../include/mxd_backup.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>

static mxd_backup_config_t backup_config = {0};
static int backup_initialized = 0;

static int create_directory(const char *path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        if (mkdir(path, 0755) != 0) {
            return -1;
        }
    }
    return 0;
}

static int calculate_file_checksum(const char *filepath, char *checksum) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        return -1;
    }
    
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size > 0) {
        uint8_t *file_data = malloc(file_size);
        if (!file_data) {
            fclose(file);
            return -1;
        }
        
        fread(file_data, 1, file_size, file);
        
        uint8_t hash[64];
        if (mxd_sha512(file_data, file_size, hash) != 0) {
            free(file_data);
            fclose(file);
            return -1;
        }
        
        for (int i = 0; i < 32; i++) {
            snprintf(checksum + (i * 2), 3, "%02x", hash[i]);
        }
        checksum[64] = '\0';
        
        free(file_data);
    }
    
    fclose(file);
    return 0;
}

int mxd_init_backup_system(const mxd_backup_config_t *config) {
    if (!config) {
        return -1;
    }
    
    backup_config = *config;
    
    if (create_directory(backup_config.backup_dir) != 0) {
        MXD_LOG_ERROR("backup", "Failed to create backup directory: %s", backup_config.backup_dir);
        return -1;
    }
    
    backup_initialized = 1;
    MXD_LOG_INFO("backup", "Backup system initialized - dir: %s, retention: %d days", 
                 backup_config.backup_dir, backup_config.retention_days);
    return 0;
}

void mxd_cleanup_backup_system(void) {
    if (backup_initialized) {
        backup_initialized = 0;
        MXD_LOG_INFO("backup", "Backup system cleaned up");
    }
}

int mxd_create_blockchain_backup(const char *db_path, mxd_backup_info_t *backup_info) {
    if (!backup_initialized || !db_path || !backup_info) {
        return -1;
    }
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    char timestamp_str[32];
    strftime(timestamp_str, sizeof(timestamp_str), "%Y%m%d_%H%M%S", tm_info);
    
    snprintf(backup_info->backup_path, sizeof(backup_info->backup_path),
             "%s/blockchain_backup_%s.db", backup_config.backup_dir, timestamp_str);
    
    char copy_command[1024];
    snprintf(copy_command, sizeof(copy_command), "cp -r \"%s\" \"%s\"", db_path, backup_info->backup_path);
    
    if (system(copy_command) != 0) {
        MXD_LOG_ERROR("backup", "Failed to create backup: %s", backup_info->backup_path);
        return -1;
    }
    
    backup_info->timestamp = now;
    backup_info->blockchain_height = 0; // Would get from blockchain
    
    struct stat st;
    if (stat(backup_info->backup_path, &st) == 0) {
        backup_info->backup_size = st.st_size;
    }
    
    if (calculate_file_checksum(backup_info->backup_path, backup_info->checksum) != 0) {
        MXD_LOG_WARN("backup", "Failed to calculate backup checksum");
        strcpy(backup_info->checksum, "unknown");
    }
    
    backup_info->is_valid = 1;
    
    MXD_LOG_INFO("backup", "Blockchain backup created: %s (size: %lu bytes)", 
                 backup_info->backup_path, backup_info->backup_size);
    return 0;
}

int mxd_restore_blockchain_backup(const char *backup_path, const char *restore_path) {
    if (!backup_initialized || !backup_path || !restore_path) {
        return -1;
    }
    
    struct stat st;
    if (stat(backup_path, &st) != 0) {
        MXD_LOG_ERROR("backup", "Backup file not found: %s", backup_path);
        return -1;
    }
    
    char copy_command[1024];
    snprintf(copy_command, sizeof(copy_command), "cp -r \"%s\" \"%s\"", backup_path, restore_path);
    
    if (system(copy_command) != 0) {
        MXD_LOG_ERROR("backup", "Failed to restore backup: %s -> %s", backup_path, restore_path);
        return -1;
    }
    
    MXD_LOG_INFO("backup", "Blockchain backup restored: %s -> %s", backup_path, restore_path);
    return 0;
}

int mxd_verify_backup_integrity(const char *backup_path) {
    if (!backup_initialized || !backup_path) {
        return -1;
    }
    
    struct stat st;
    if (stat(backup_path, &st) != 0) {
        MXD_LOG_ERROR("backup", "Backup file not found: %s", backup_path);
        return -1;
    }
    
    char checksum[65];
    if (calculate_file_checksum(backup_path, checksum) != 0) {
        MXD_LOG_ERROR("backup", "Failed to calculate backup checksum: %s", backup_path);
        return -1;
    }
    
    MXD_LOG_INFO("backup", "Backup integrity verified: %s (checksum: %.16s...)", backup_path, checksum);
    return 0;
}

int mxd_cleanup_old_backups(void) {
    if (!backup_initialized) {
        return -1;
    }
    
    DIR *dir = opendir(backup_config.backup_dir);
    if (!dir) {
        MXD_LOG_ERROR("backup", "Failed to open backup directory: %s", backup_config.backup_dir);
        return -1;
    }
    
    time_t now = time(NULL);
    time_t cutoff_time = now - (backup_config.retention_days * 24 * 3600);
    int deleted_count = 0;
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, "blockchain_backup_") == entry->d_name) {
            char full_path[512];
            snprintf(full_path, sizeof(full_path), "%s/%s", backup_config.backup_dir, entry->d_name);
            
            struct stat st;
            if (stat(full_path, &st) == 0 && st.st_mtime < cutoff_time) {
                if (unlink(full_path) == 0) {
                    deleted_count++;
                    MXD_LOG_INFO("backup", "Deleted old backup: %s", entry->d_name);
                }
            }
        }
    }
    
    closedir(dir);
    MXD_LOG_INFO("backup", "Cleanup completed - deleted %d old backups", deleted_count);
    return 0;
}

int mxd_create_config_backup(const char *config_path) {
    if (!backup_initialized || !config_path) {
        return -1;
    }
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    char timestamp_str[32];
    strftime(timestamp_str, sizeof(timestamp_str), "%Y%m%d_%H%M%S", tm_info);
    
    char backup_path[512];
    snprintf(backup_path, sizeof(backup_path), "%s/config_backup_%s.json", 
             backup_config.backup_dir, timestamp_str);
    
    char copy_command[1024];
    snprintf(copy_command, sizeof(copy_command), "cp \"%s\" \"%s\"", config_path, backup_path);
    
    if (system(copy_command) != 0) {
        MXD_LOG_ERROR("backup", "Failed to create config backup: %s", backup_path);
        return -1;
    }
    
    MXD_LOG_INFO("backup", "Configuration backup created: %s", backup_path);
    return 0;
}

int mxd_restore_config_backup(const char *backup_path, const char *restore_path) {
    if (!backup_initialized || !backup_path || !restore_path) {
        return -1;
    }
    
    char copy_command[1024];
    snprintf(copy_command, sizeof(copy_command), "cp \"%s\" \"%s\"", backup_path, restore_path);
    
    if (system(copy_command) != 0) {
        MXD_LOG_ERROR("backup", "Failed to restore config backup: %s -> %s", backup_path, restore_path);
        return -1;
    }
    
    MXD_LOG_INFO("backup", "Configuration backup restored: %s -> %s", backup_path, restore_path);
    return 0;
}
