#include "../include/mxd_secrets.h"
#include "../include/mxd_logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static mxd_secrets_t secrets = {0};
static int secrets_initialized = 0;

static void secure_zero(void *ptr, size_t size) {
    volatile uint8_t *p = (volatile uint8_t*)ptr;
    while (size--) {
        *p++ = 0;
    }
}

static int fill_random(void *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t r = fread(buf, 1, len, f);
    fclose(f);
    return r == len ? 0 : -1;
}

int mxd_init_secrets(const char *config_file) {
    secure_zero(&secrets, sizeof(secrets));
    
    int have_magic = 0;
    int have_salt = 0;

    if (mxd_load_secret_from_env("MXD_NETWORK_MAGIC", &secrets.network_magic, sizeof(secrets.network_magic)) == 0) {
        have_magic = 1;
        MXD_LOG_INFO("secrets", "Loaded network magic from environment");
    }
    
    if (mxd_load_secret_from_env("MXD_CRYPTO_SALT", secrets.crypto_salt, sizeof(secrets.crypto_salt)) == 0) {
        have_salt = 1;
        MXD_LOG_INFO("secrets", "Loaded crypto salt from environment");
    }
    
    if (!have_magic) {
        if (fill_random(&secrets.network_magic, sizeof(secrets.network_magic)) != 0) {
            MXD_LOG_ERROR("secrets", "Failed to generate network magic");
            return -1;
        }
        MXD_LOG_WARN("secrets", "Generated development-only network magic");
    }
    
    if (!have_salt) {
        if (fill_random(secrets.crypto_salt, sizeof(secrets.crypto_salt)) != 0) {
            MXD_LOG_ERROR("secrets", "Failed to generate crypto salt");
            return -1;
        }
        MXD_LOG_WARN("secrets", "Generated development-only crypto salt");
    }

    if (mxd_load_secret_from_env("MXD_BOOTSTRAP_API_KEY", secrets.bootstrap_api_key, sizeof(secrets.bootstrap_api_key)) == 0) {
        MXD_LOG_INFO("secrets", "Loaded bootstrap API key from environment");
    }
    
    if (mxd_load_secret_from_env("MXD_DB_ENCRYPTION_KEY", secrets.database_encryption_key, sizeof(secrets.database_encryption_key)) == 0) {
        MXD_LOG_INFO("secrets", "Loaded database encryption key from environment");
    }
    
    secrets_initialized = 1;
    MXD_LOG_INFO("secrets", "Secrets management initialized");
    return 0;
}

void mxd_cleanup_secrets(void) {
    if (secrets_initialized) {
        secure_zero(&secrets, sizeof(secrets));
        secrets_initialized = 0;
        MXD_LOG_INFO("secrets", "Secrets cleared from memory");
    }
}

const mxd_secrets_t* mxd_get_secrets(void) {
    if (!secrets_initialized) {
        if (mxd_init_secrets(NULL) != 0) {
            return NULL;
        }
    }
    return &secrets;
}

int mxd_load_secret_from_env(const char *env_var, void *dest, size_t dest_size) {
    if (!env_var || !dest || dest_size == 0) {
        return -1;
    }
    
    const char *value = getenv(env_var);
    if (!value) {
        return -1;
    }
    
    size_t value_len = strlen(value);
    if (value_len >= dest_size) {
        MXD_LOG_ERROR("secrets", "Environment variable %s value too large", env_var);
        return -1;
    }
    
    memcpy(dest, value, value_len);
    memset((uint8_t*)dest + value_len, 0, dest_size - value_len);
    
    return 0;
}
