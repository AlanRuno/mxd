#ifndef MXD_RSC_H
#define MXD_RSC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../common/mxd_metrics_types.h"
#include <stddef.h>
#include <stdint.h>

// RSC (Response Speed Consensus) specific functions can be added here

// Validator public key registry functions
int mxd_test_register_validator_pubkey(const uint8_t *validator_id, const uint8_t *pub, size_t pub_len);
int mxd_get_validator_public_key(const uint8_t *validator_id, uint8_t *out_key, size_t out_capacity, size_t *out_len);
int mxd_get_validator_algo_id(const uint8_t *validator_id, uint8_t *out_algo_id);
void mxd_test_clear_validator_pubkeys(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_RSC_H
