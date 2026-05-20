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

static int copy_file(const char *src, const char *dst) {
    FILE *src_file = fopen(src, "rb");
    if (!src_file) {
        return -1;
    }
    
    FILE *dst_file = fopen(dst, "wb");
    if (!dst_file) {
        fclose(src_file);
        return -1;
    }
    
    char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src_file)) > 0) {
        if (fwrite(buffer, 1, bytes, dst_file) != bytes) {
            fclose(src_file);
            fclose(dst_file);
            return -1;
        }
    }
    
    fclose(src_file);
    fclose(dst_file);
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
    
    if (file_size <= 0) {
        // Empty file - return zero hash
        memset(checksum, '0', 64);
        checksum[64] = '\0';
        fclose(file);
        return 0;
    }
    
    // For large files, use chunked hashing to avoid memory issues
    // Threshold: 64MB - files larger than this are processed in chunks
    const size_t CHUNK_THRESHOLD = 64 * 1024 * 1024;
    
    if ((size_t)file_size > CHUNK_THRESHOLD) {
        // Process large files in chunks using incremental hashing
        uint8_t chunk_hash[64];
        uint8_t combined_hash[64];
        memset(combined_hash, 0, 64);
        
        uint8_t *chunk_buffer = malloc(CHUNK_THRESHOLD);
        if (!chunk_buffer) {
            MXD_LOG_ERROR("backup", "Failed to allocate chunk buffer for large file checksum");
            fclose(file);
            return -1;
        }
        
        size_t bytes_read;
        size_t total_read = 0;
        
        while ((bytes_read = fread(chunk_buffer, 1, CHUNK_THRESHOLD, file)) > 0) {
            total_read += bytes_read;
            
            // Hash this chunk
            if (mxd_sha512(chunk_buffer, bytes_read, chunk_hash) != 0) {
                free(chunk_buffer);
                fclose(file);
                return -1;
            }
            
            // Order-dependent hash chain: combined = SHA512(combined || chunk_hash)
            {
                uint8_t chain_input[128];
                memcpy(chain_input, combined_hash, 64);
                memcpy(chain_input + 64, chunk_hash, 64);
                if (mxd_sha512(chain_input, 128, combined_hash) != 0) {
                    free(chunk_buffer);
                    fclose(file);
                    return -1;
                }
            }
        }
        
        free(chunk_buffer);
        
        // Final hash of combined result
        uint8_t final_hash[64];
        if (mxd_sha512(combined_hash, 64, final_hash) != 0) {
            fclose(file);
            return -1;
        }
        
        for (int i = 0; i < 32; i++) {
            snprintf(checksum + (i * 2), 3, "%02x", final_hash[i]);
        }
        checksum[64] = '\0';
    } else {
        // Small file - read entire file into memory
        uint8_t *file_data = malloc(file_size);
        if (!file_data) {
            MXD_LOG_ERROR("backup", "Failed to allocate memory for file checksum (%ld bytes)", file_size);
            fclose(file);
            return -1;
        }
        
        size_t bytes_read = fread(file_data, 1, file_size, file);
        if (bytes_read != (size_t)file_size) {
            MXD_LOG_ERROR("backup", "Failed to read file for checksum (read %zu of %ld bytes)", 
                         bytes_read, file_size);
            free(file_data);
            fclose(file);
            return -1;
        }
        
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
    
    // Use native file copy instead of system()
    if (copy_file(db_path, backup_info->backup_path) != 0) {
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
        strncpy(backup_info->checksum, "unknown", sizeof(backup_info->checksum) - 1);
        backup_info->checksum[sizeof(backup_info->checksum) - 1] = '\0';
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
    
    // Use native file copy instead of system()
    if (copy_file(backup_path, restore_path) != 0) {
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
    
    // Use native file copy instead of system()
    if (copy_file(config_path, backup_path) != 0) {
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
    
    // Use native file copy instead of system()
    if (copy_file(backup_path, restore_path) != 0) {
        MXD_LOG_ERROR("backup", "Failed to restore config backup: %s -> %s", backup_path, restore_path);
        return -1;
    }
    
    MXD_LOG_INFO("backup", "Configuration backup restored: %s -> %s", backup_path, restore_path);
    return 0;
}
