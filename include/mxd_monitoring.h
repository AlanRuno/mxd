#ifndef MXD_MONITORING_H
#define MXD_MONITORING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include "mxd_types.h"
#include "mxd_metrics.h"
#include "mxd_address.h"
#include "mxd_transaction.h"
#include "mxd_utxo.h"

typedef struct {
    uint64_t total_transactions;
    uint64_t total_blocks;
    double current_tps;
    uint64_t network_latency_ms;
    uint32_t active_peers;
    uint64_t blockchain_height;
    double consensus_efficiency;
    uint64_t memory_usage_bytes;
    uint64_t disk_usage_bytes;
    double cpu_usage_percent;
} mxd_system_metrics_t;

typedef struct {
    int is_healthy;
    int database_connected;
    int p2p_active;
    int consensus_active;
    char status_message[256];
    uint64_t last_check_timestamp;
} mxd_health_status_t;

typedef struct {
    char address[42];
    uint8_t algo_id;
    uint16_t public_key_length;
    uint8_t *public_key;
    uint16_t private_key_length;
    uint8_t *private_key;
    char passphrase[256];
} mxd_wallet_keypair_t;

typedef struct {
    mxd_wallet_keypair_t keypairs[10];
    size_t keypair_count;
} mxd_wallet_t;

int mxd_init_monitoring(uint16_t http_port);
void mxd_cleanup_monitoring(void);
int mxd_update_system_metrics(const mxd_system_metrics_t *metrics);
int mxd_get_health_status(mxd_health_status_t *status);
int mxd_start_metrics_server(void);
int mxd_stop_metrics_server(void);

const char* mxd_get_prometheus_metrics(void);
const char* mxd_get_health_json(void);

int mxd_init_wallet(void);
void mxd_cleanup_wallet(void);
const char* mxd_get_wallet_html(void);
const char* mxd_handle_wallet_generate(void);
const char* mxd_handle_wallet_balance(const char* address);
const char* mxd_handle_wallet_send(const char* recipient, const char* amount);

// Wallet persistence and export/import
int mxd_save_wallet_to_file(const char* filepath);
int mxd_load_wallet_from_file(const char* filepath);
const char* mxd_handle_wallet_export(const char* password);
const char* mxd_handle_wallet_import(const char* encrypted_data, const char* password);
const char* mxd_handle_wallet_list_addresses(void);

// Transaction history
typedef struct {
    char txid[129];
    char from_address[64];
    char to_address[64];
    mxd_amount_t amount;  // Amount in base units
    uint64_t timestamp;
    uint8_t algo_id;
    char status[32];
} mxd_transaction_history_entry_t;

int mxd_add_transaction_to_history(const char* txid, const char* from_addr, 
                                    const char* to_addr, mxd_amount_t amount, 
                                    uint64_t timestamp, uint8_t algo_id);
const char* mxd_handle_wallet_transaction_history(const char* address);

// Hybrid crypto metrics
typedef struct {
    uint32_t ed25519_addresses;
    uint32_t dilithium5_addresses;
    uint32_t ed25519_transactions;
    uint32_t dilithium5_transactions;
    mxd_amount_t ed25519_volume;    // Volume in base units
    mxd_amount_t dilithium5_volume; // Volume in base units
} mxd_hybrid_crypto_metrics_t;

int mxd_update_hybrid_crypto_metrics(const mxd_hybrid_crypto_metrics_t* metrics);
const char* mxd_get_hybrid_crypto_metrics_json(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_MONITORING_H
