#ifndef MXD_SECRETS_H
#define MXD_SECRETS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t network_magic;
    uint8_t crypto_salt[32];
    char bootstrap_api_key[256];
    char database_encryption_key[64];
} mxd_secrets_t;

int mxd_init_secrets(const char *config_file);
void mxd_cleanup_secrets(void);
const mxd_secrets_t* mxd_get_secrets(void);
int mxd_load_secret_from_env(const char *env_var, void *dest, size_t dest_size);

#ifdef __cplusplus
}
#endif

#endif // MXD_SECRETS_H
