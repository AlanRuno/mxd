#include "../include/mxd_http_api.h"
#include "../include/mxd_blockchain_db.h"
#include "../include/mxd_blockchain.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_endian.h"
#include "../include/mxd_mempool.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_address.h"
#include "../include/mxd_config.h"
#include "../include/mxd_utxo.h"
#include "../include/mxd_p2p.h"
#include "../include/mxd_rsc.h"
#include "../include/mxd_smart_contracts.h"
#include "../include/mxd_contracts_db.h"
#include "../include/mxd_gas_metering.h"
#include "../include/mxd_domain_tags.h"
#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <cjson/cJSON.h>
#include <wasm3/wasm3.h>
#include <sodium.h>

// Connection context for POST data accumulation
typedef struct {
    char *post_data;
    size_t post_data_size;
} connection_info_t;

static struct MHD_Daemon *http_daemon = NULL;

// Check API authentication for mutation endpoints.
// Returns 1 if authorized, 0 if unauthorized.
static int check_api_auth(struct MHD_Connection *connection) {
    mxd_config_t *cfg = mxd_get_config();
    if (!cfg || !cfg->http.require_auth) {
        return 1; // Auth not required
    }
    if (cfg->http.api_token[0] == '\0') {
        MXD_LOG_ERROR("http_api", "require_auth is set but api_token is empty");
        return 0;
    }

    const char *auth_header = MHD_lookup_connection_value(
        connection, MHD_HEADER_KIND, "Authorization");
    if (!auth_header) {
        return 0;
    }

    // Expect "Bearer <token>"
    if (strncmp(auth_header, "Bearer ", 7) != 0) {
        return 0;
    }
    const char *token = auth_header + 7;
    size_t token_len = strlen(token);
    size_t expected_len = strlen(cfg->http.api_token);
    if (token_len != expected_len) {
        return 0;
    }
    // Constant-time comparison to prevent timing attacks
    return sodium_memcmp(token, cfg->http.api_token, expected_len) == 0 ? 1 : 0;
}

// Send a JSON error response
static enum MHD_Result send_json_error(struct MHD_Connection *connection,
                                        int status_code, const char *error_msg) {
    char *json = malloc(256);
    if (!json) return MHD_NO;
    snprintf(json, 256, "{\"error\":\"%s\"}", error_msg);
    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(json), json, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(response, "Content-Type", "application/json");
    enum MHD_Result ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);
    return ret;
}

// Helper to convert block to JSON
// Helper: convert bytes to hex string (caller provides buffer of at least len*2+1)
static void bytes_to_hex(const uint8_t *bytes, size_t len, char *out) {
    for (size_t i = 0; i < len; i++) snprintf(out + i*2, 3, "%02x", bytes[i]);
}

// A2 helper: surface BSC-side bridge context for bridge_mint transactions.
// The data is committed on-chain inside the v3 payload but is invisible to
// explorers/audit because the v2 deserializer (which historically wins for
// bridge mints because they look like coinbases) doesn't know how to extract
// it. Calling this from both code paths exposes a stable `bridge_data` object
// to API consumers without changing any existing field.
// Aditive — does not replace any v2/v3 field; existing clients ignore it.
static void add_bridge_data_json(cJSON *tx_obj, const mxd_bridge_payload_t *bridge) {
    if (!tx_obj || !bridge) return;
    cJSON *bd = cJSON_AddObjectToObject(tx_obj, "bridge_data");
    if (!bd) return;

    char hex[129];

    // source_chain_id: stored as BE u32 in first 4 bytes of the 32-byte field.
    uint32_t chain_id_be;
    memcpy(&chain_id_be, bridge->source_chain_id, sizeof(uint32_t));
    uint32_t chain_id = ntohl(chain_id_be);
    cJSON_AddNumberToObject(bd, "source_chain_id", chain_id);
    const char *chain_name = (chain_id == 56) ? "bsc_mainnet_56"
                           : (chain_id == 97) ? "bsc_testnet_97"
                           : "unknown";
    cJSON_AddStringToObject(bd, "source_chain_name", chain_name);

    // bsc_tx_hash: 32 bytes = 64 hex chars. Prefix with "0x" for BSC convention
    // so explorers can use it as-is in BscScan links.
    char bsc_tx_hash_prefixed[67];      // "0x" + 64 hex + NUL
    bsc_tx_hash_prefixed[0] = '0';
    bsc_tx_hash_prefixed[1] = 'x';
    bytes_to_hex(bridge->source_tx_hash, 32, bsc_tx_hash_prefixed + 2);
    bsc_tx_hash_prefixed[66] = '\0';
    cJSON_AddStringToObject(bd, "bsc_tx_hash", bsc_tx_hash_prefixed);

    cJSON_AddNumberToObject(bd, "source_block_number", (double)bridge->source_block_number);

    // bridge_contract: 64-byte SHA-512 contract hash, 128 hex chars.
    bytes_to_hex(bridge->bridge_contract, 64, hex); hex[128] = 0;
    cJSON_AddStringToObject(bd, "bridge_contract", hex);

    // mxd_chain_id: first 4 bytes BE u32, expose as hex (4D580001/4D580002).
    bytes_to_hex(bridge->mxd_chain_id, 4, hex); hex[8] = 0;
    cJSON_AddStringToObject(bd, "mxd_chain_id", hex);

    // oracle_count: how many K-of-N attestations are committed in the payload.
    cJSON_AddNumberToObject(bd, "oracle_count", (double)bridge->oracle_count);
}

static char* block_to_json(const mxd_block_t *block) {
    if (!block) return NULL;

    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    char hex[129];

    // Block header
    cJSON_AddNumberToObject(root, "height", block->height);
    bytes_to_hex(block->block_hash, 64, hex); hex[128] = 0;
    cJSON_AddStringToObject(root, "hash", hex);
    bytes_to_hex(block->prev_block_hash, 64, hex); hex[128] = 0;
    cJSON_AddStringToObject(root, "prev_hash", hex);
    bytes_to_hex(block->merkle_root, 64, hex); hex[128] = 0;
    cJSON_AddStringToObject(root, "merkle_root", hex);
    cJSON_AddNumberToObject(root, "timestamp", (double)block->timestamp);
    bytes_to_hex(block->proposer_id, 32, hex); hex[64] = 0;   // v6: addr32 (64 hex chars)
    cJSON_AddStringToObject(root, "proposer", hex);
    cJSON_AddNumberToObject(root, "version", block->version);
    cJSON_AddNumberToObject(root, "difficulty", block->difficulty);
    cJSON_AddNumberToObject(root, "nonce", (double)block->nonce);
    cJSON_AddNumberToObject(root, "transaction_count", block->transaction_count);
    cJSON_AddNumberToObject(root, "validation_count", block->validation_count);
    cJSON_AddNumberToObject(root, "rapid_membership_count", block->rapid_membership_count);
    cJSON_AddNumberToObject(root, "total_supply", (double)block->total_supply);

    if (block->version >= 5) {
        // v6: next_proposer is 32-byte addr32 (was 20 bytes in v5).
        size_t np_len = (block->version >= 6) ? 32 : 20;
        bytes_to_hex(block->next_proposer, np_len, hex); hex[np_len * 2] = 0;
        cJSON_AddStringToObject(root, "next_proposer", hex);
    }

    // Transactions
    cJSON *tx_array = cJSON_AddArrayToObject(root, "transactions");
    for (uint32_t t = 0; t < block->transaction_count && block->transactions; t++) {
        const uint8_t *data = block->transactions[t].data;
        size_t len = block->transactions[t].length;
        if (!data || len == 0) continue;

        // Try v2 deserialization first, then v3
        mxd_transaction_t tx;
        memset(&tx, 0, sizeof(tx));

        if (mxd_deserialize_transaction(data, len, &tx) == 0) {
            /* tx_hash is populated from the wire (MXD-04 §10.1 pre-parse dedup hint). */
            cJSON *tx_obj = cJSON_CreateObject();

            bytes_to_hex(tx.tx_hash, 64, hex); hex[128] = 0;
            cJSON_AddStringToObject(tx_obj, "hash", hex);
            cJSON_AddNumberToObject(tx_obj, "version", tx.version);
            cJSON_AddBoolToObject(tx_obj, "is_coinbase", tx.is_coinbase);
            cJSON_AddNumberToObject(tx_obj, "timestamp", (double)tx.timestamp);
            cJSON_AddNumberToObject(tx_obj, "input_count", tx.input_count);
            cJSON_AddNumberToObject(tx_obj, "output_count", tx.output_count);
            if (tx.voluntary_tip > 0)
                cJSON_AddNumberToObject(tx_obj, "voluntary_tip", (double)tx.voluntary_tip);

            // Inputs
            cJSON *inputs = cJSON_AddArrayToObject(tx_obj, "inputs");
            for (uint32_t i = 0; i < tx.input_count && tx.inputs; i++) {
                cJSON *in = cJSON_CreateObject();
                bytes_to_hex(tx.inputs[i].prev_tx_hash, 64, hex); hex[128] = 0;
                cJSON_AddStringToObject(in, "prev_tx_hash", hex);
                cJSON_AddNumberToObject(in, "output_index", tx.inputs[i].output_index);
                cJSON_AddNumberToObject(in, "amount", (double)tx.inputs[i].amount);
                cJSON_AddNumberToObject(in, "algo_id", tx.inputs[i].algo_id);
                cJSON_AddItemToArray(inputs, in);
            }

            // Outputs
            cJSON *outputs = cJSON_AddArrayToObject(tx_obj, "outputs");
            for (uint32_t i = 0; i < tx.output_count && tx.outputs; i++) {
                cJSON *out = cJSON_CreateObject();
                bytes_to_hex(tx.outputs[i].recipient_addr, 32, hex); hex[64] = 0;
                cJSON_AddStringToObject(out, "recipient", hex);
                cJSON_AddNumberToObject(out, "amount", (double)tx.outputs[i].amount);
                cJSON_AddItemToArray(outputs, out);
            }

            // A2: v3 bridge_mint txs are structurally parseable as v2 coinbases
            // (no inputs, single output). The v2 path doesn't extract the
            // payload.bridge, so we re-deserialize as v3 just to surface the
            // BSC-side context. Cheap (no allocation outside cJSON), additive.
            if (tx.version == 3) {
                mxd_transaction_v3_t tx3_for_bridge;
                memset(&tx3_for_bridge, 0, sizeof(tx3_for_bridge));
                if (mxd_deserialize_transaction_v3_from_block(data, len, &tx3_for_bridge) == 0) {
                    if (tx3_for_bridge.type == MXD_TX_TYPE_BRIDGE_MINT &&
                        tx3_for_bridge.payload.bridge) {
                        add_bridge_data_json(tx_obj, tx3_for_bridge.payload.bridge);
                    }
                    mxd_free_transaction_v3(&tx3_for_bridge);
                }
            }

            cJSON_AddItemToArray(tx_array, tx_obj);
            mxd_free_transaction(&tx);
        } else {
            // Try v3
            mxd_transaction_v3_t tx3;
            memset(&tx3, 0, sizeof(tx3));
            if (mxd_deserialize_transaction_v3_from_block(data, len, &tx3) == 0) {
                cJSON *tx_obj = cJSON_CreateObject();

                bytes_to_hex(tx3.tx_hash, 64, hex); hex[128] = 0;
                cJSON_AddStringToObject(tx_obj, "hash", hex);
                cJSON_AddNumberToObject(tx_obj, "version", tx3.version);
                cJSON_AddNumberToObject(tx_obj, "type", tx3.type);
                cJSON_AddNumberToObject(tx_obj, "timestamp", (double)tx3.timestamp);
                cJSON_AddNumberToObject(tx_obj, "output_count", tx3.output_count);

                cJSON *outputs = cJSON_AddArrayToObject(tx_obj, "outputs");
                for (uint32_t i = 0; i < tx3.output_count && tx3.outputs; i++) {
                    cJSON *out = cJSON_CreateObject();
                    bytes_to_hex(tx3.outputs[i].recipient_addr, 32, hex); hex[64] = 0;
                    cJSON_AddStringToObject(out, "recipient", hex);
                    cJSON_AddNumberToObject(out, "amount", (double)tx3.outputs[i].amount);
                    cJSON_AddItemToArray(outputs, out);
                }

                // A2: surface BSC-side bridge context for bridge_mint txs that
                // reached this path (e.g., when the v2 deserializer happened to
                // fail). Same helper as the v2-success branch above.
                if (tx3.type == MXD_TX_TYPE_BRIDGE_MINT && tx3.payload.bridge) {
                    add_bridge_data_json(tx_obj, tx3.payload.bridge);
                }

                cJSON_AddItemToArray(tx_array, tx_obj);
                mxd_free_transaction_v3(&tx3);
            } else {
                // Unparseable — include raw hex
                cJSON *tx_obj = cJSON_CreateObject();
                cJSON_AddStringToObject(tx_obj, "error", "unparseable");
                cJSON_AddNumberToObject(tx_obj, "raw_length", (double)len);
                cJSON_AddItemToArray(tx_array, tx_obj);
            }
        }
    }

    char *result = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return result;
}

// Helper to parse hex string to bytes
static int hex_to_bytes(const char *hex, uint8_t *bytes, size_t max_len) {
    if (!hex || !bytes) return -1;
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0 || hex_len / 2 > max_len) return -1;
    
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        bytes[i] = (uint8_t)byte;
    }
    return (int)(hex_len / 2);
}

// Handle POST /transaction endpoint - submit a pre-signed transaction
// SECURITY: Accepts pre-signed serialized transaction bytes only.
// The client must construct, sign, and serialize the transaction locally.
// Required field: "signed_tx" (hex-encoded serialized transaction bytes)
char* handle_transaction_submit(const char *post_data, int *status_code) {
    *status_code = MHD_HTTP_OK;

    if (!post_data || strlen(post_data) == 0) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Empty request body\"}");
    }

    cJSON *json = cJSON_Parse(post_data);
    if (!json) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid JSON\"}");
    }

    // SECURITY FIX (C-06): Reject any request that sends a private key
    if (cJSON_GetObjectItem(json, "private_key")) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Sending private keys to the API is not supported. "
                      "Sign transactions locally and submit the signed_tx hex.\"}");
    }

    // Accept pre-signed serialized transaction
    cJSON *signed_tx_hex = cJSON_GetObjectItem(json, "signed_tx");
    if (!signed_tx_hex || !cJSON_IsString(signed_tx_hex)) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Missing required field: signed_tx (hex-encoded serialized transaction)\"}");
    }

    const char *hex_str = signed_tx_hex->valuestring;
    size_t hex_len = strlen(hex_str);
    if (hex_len < 2 || hex_len % 2 != 0 || hex_len > 2 * 1048576) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid signed_tx hex length\"}");
    }

    size_t tx_data_len = hex_len / 2;
    uint8_t *tx_data = malloc(tx_data_len);
    if (!tx_data) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    if (hex_to_bytes(hex_str, tx_data, tx_data_len) != (int)tx_data_len) {
        free(tx_data);
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid hex encoding in signed_tx\"}");
    }
    cJSON_Delete(json);

    // Deserialize the transaction
    mxd_transaction_t tx;
    memset(&tx, 0, sizeof(tx));
    if (mxd_deserialize_transaction(tx_data, tx_data_len, &tx) != 0) {
        free(tx_data);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Failed to deserialize transaction\"}");
    }

    // SECURITY: Reject coinbase transactions via API — only block proposer may create these
    if (tx.is_coinbase) {
        mxd_free_transaction(&tx);
        free(tx_data);
        *status_code = MHD_HTTP_FORBIDDEN;
        return strdup("{\"error\":\"Coinbase transactions cannot be submitted via API\"}");
    }

    // Log transaction details for debugging
    {
        char hash_hex[129] = {0};
        for (int i = 0; i < 64; i++) snprintf(hash_hex + i*2, 3, "%02x", tx.tx_hash[i]);
        MXD_LOG_INFO("http_api", "TX submit: v=%u inputs=%u outputs=%u algo=%u pubkey_len=%u sig_len=%u hash=%s",
                     tx.version, tx.input_count, tx.output_count,
                     tx.input_count > 0 ? tx.inputs[0].algo_id : 0,
                     tx.input_count > 0 ? tx.inputs[0].public_key_length : 0,
                     tx.input_count > 0 ? tx.inputs[0].signature_length : 0,
                     hash_hex);

        // Recalculate hash to compare
        uint8_t recalc_hash[64];
        mxd_calculate_tx_hash(&tx, recalc_hash);
        char recalc_hex[129] = {0};
        for (int i = 0; i < 64; i++) snprintf(recalc_hex + i*2, 3, "%02x", recalc_hash[i]);
        MXD_LOG_INFO("http_api", "TX hash submitted: %s", hash_hex);
        MXD_LOG_INFO("http_api", "TX hash recalculated: %s", recalc_hex);
        MXD_LOG_INFO("http_api", "TX hash match: %s", memcmp(tx.tx_hash, recalc_hash, 64) == 0 ? "YES" : "NO");
    }

    // Validate the transaction (checks signatures, inputs, outputs, etc.)
    if (mxd_validate_transaction(&tx) != 0) {
        MXD_LOG_ERROR("http_api", "TX validation failed: v=%u inputs=%u outputs=%u coinbase=%u",
                      tx.version, tx.input_count, tx.output_count, tx.is_coinbase);
        if (tx.input_count > 0) {
            MXD_LOG_ERROR("http_api", "  Input 0: algo=%u pubkey_len=%u sig_len=%u",
                          tx.inputs[0].algo_id, tx.inputs[0].public_key_length, tx.inputs[0].signature_length);
        }
        mxd_free_transaction(&tx);
        free(tx_data);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Transaction validation failed (invalid signature or structure)\"}");
    }

    // Compute the canonical tx_hash and write it into tx.tx_hash. The wire
    // bytes carried whatever hash the wallet computed; the node is the
    // authority on tx_hash and the mempool MUST hold the canonical value
    // so mxd_remove_from_mempool's recomputation matches at evict time.
    // Otherwise the tx never gets evicted and the proposer re-includes it
    // in N consecutive blocks until age-based cleanup. (Symptom: same tx
    // bytes appear in /block/h for h..h+3.)
    if (mxd_calculate_tx_hash(&tx, tx.tx_hash) != 0) {
        mxd_free_transaction(&tx);
        free(tx_data);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to calculate transaction hash\"}");
    }

    // Add to mempool with medium priority
    if (mxd_add_to_mempool(&tx, MXD_PRIORITY_MEDIUM) != 0) {
        mxd_free_transaction(&tx);
        free(tx_data);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to add transaction to mempool\"}");
    }

    // Broadcast transaction to all peers
    mxd_broadcast_message(MXD_MSG_TRANSACTIONS, tx_data, tx_data_len);
    free(tx_data);

    // Build success response with transaction hash (canonical, from tx.tx_hash)
    char tx_hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) {
        snprintf(tx_hash_hex + i*2, 3, "%02x", tx.tx_hash[i]);
    }

    char *response = malloc(256);
    snprintf(response, 256, "{\"success\":true,\"tx_hash\":\"%s\"}", tx_hash_hex);

    mxd_free_transaction(&tx);

    MXD_LOG_INFO("http_api", "Transaction submitted: %s", tx_hash_hex);
    return response;
}

// Handle GET /validators endpoint - list RSC members from genesis
static char* handle_validators(int *status_code) {
    *status_code = MHD_HTTP_OK;

    mxd_block_t genesis;
    if (mxd_retrieve_block_by_height(0, &genesis) != 0) {
        *status_code = MHD_HTTP_NOT_FOUND;
        return strdup("{\"error\":\"Genesis block not found\"}");
    }

    // Build JSON response
    size_t buf_size = 256 + genesis.rapid_membership_count * 256;
    char *response = malloc(buf_size);
    if (!response) {
        mxd_free_block(&genesis);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    int offset = snprintf(response, buf_size, "{\"count\":%u,\"validators\":[", genesis.rapid_membership_count);

    for (uint32_t i = 0; i < genesis.rapid_membership_count && genesis.rapid_membership_entries; i++) {
        mxd_rapid_membership_entry_t *entry = &genesis.rapid_membership_entries[i];

        // Convert address to hex (v6: addr32)
        char addr_hex[65] = {0};
        for (int j = 0; j < 32; j++) {
            snprintf(addr_hex + j*2, 3, "%02x", entry->node_address[j]);
        }

        // Convert public key to hex (first 32 bytes for display)
        char pk_hex[65] = {0};
        int pk_display_len = entry->public_key_length < 32 ? entry->public_key_length : 32;
        for (int j = 0; j < pk_display_len; j++) {
            snprintf(pk_hex + j*2, 3, "%02x", entry->public_key[j]);
        }

        offset += snprintf(response + offset, buf_size - offset,
            "%s{\"index\":%u,\"address\":\"%s\",\"algo_id\":%u,\"public_key\":\"%s\",\"timestamp\":%lu}",
            i > 0 ? "," : "", i, addr_hex, entry->algo_id, pk_hex, (unsigned long)entry->timestamp);
    }

    snprintf(response + offset, buf_size - offset, "]}");
    mxd_free_block(&genesis);
    return response;
}

// Handle GET /node/identity endpoint - returns public identity only (no private key)
static char* handle_node_identity(int *status_code) {
    *status_code = MHD_HTTP_OK;

    uint8_t address[MXD_ADDR32_LEN];
    uint8_t pubkey[2592];
    uint8_t privkey[4896];  /* FIPS 204 ML-DSA-87 (was 4864 Round-3, updated Task 7.3) */
    size_t pubkey_len = 0, privkey_len = 0;
    uint8_t algo_id = 0;

    if (mxd_get_local_node_identity(address, pubkey, &pubkey_len, privkey, &privkey_len, &algo_id) != 0) {
        *status_code = MHD_HTTP_SERVICE_UNAVAILABLE;
        return strdup("{\"error\":\"Node identity not initialized\"}");
    }

    // Zero out private key immediately — never expose it
    memset(privkey, 0, sizeof(privkey));

    // Convert to hex strings (addr32: 64 hex chars + NUL per MXD-01 v1.1.x)
    char addr_hex[MXD_ADDR32_LEN * 2 + 1] = {0};
    for (int i = 0; i < MXD_ADDR32_LEN; i++) {
        snprintf(addr_hex + i*2, 3, "%02x", address[i]);
    }

    char *pubkey_hex = malloc(pubkey_len * 2 + 1);
    if (!pubkey_hex) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    for (size_t i = 0; i < pubkey_len; i++) {
        snprintf(pubkey_hex + i*2, 3, "%02x", pubkey[i]);
    }
    pubkey_hex[pubkey_len * 2] = '\0';

    // Build response — public info only
    size_t response_size = 256 + pubkey_len * 2;
    char *response = malloc(response_size);
    if (!response) {
        free(pubkey_hex);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    snprintf(response, response_size,
        "{\"address\":\"%s\",\"public_key\":\"%s\",\"algo_id\":%u}",
        addr_hex, pubkey_hex, algo_id);

    free(pubkey_hex);
    return response;
}

// Handle GET /rsc endpoint - get full rapid stake table
static char* handle_rsc(int *status_code) {
    *status_code = MHD_HTTP_OK;

    const mxd_rapid_table_t *table = mxd_get_rapid_table();
    if (!table) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Rapid table not available\"}");
    }

    // Build JSON response with full RSC data
    size_t buf_size = 512 + table->count * 1024;
    char *response = malloc(buf_size);
    if (!response) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    int offset = snprintf(response, buf_size,
        "{\"count\":%zu,\"last_update\":%lu,\"nodes\":[",
        table->count, (unsigned long)table->last_update);

    for (size_t i = 0; i < table->count; i++) {
        mxd_node_stake_t *node = table->nodes[i];
        if (!node) continue;

        // Convert address to hex (v6: addr32)
        char addr_hex[65] = {0};
        for (int j = 0; j < 32; j++) {
            snprintf(addr_hex + j*2, 3, "%02x", node->node_address[j]);
        }

        // Calculate stake in MXD
        double stake_mxd = (double)node->stake_amount / 100000000.0;

        offset += snprintf(response + offset, buf_size - offset,
            "%s{"
            "\"index\":%zu,"
            "\"node_id\":\"%s\","
            "\"address\":\"%s\","
            "\"stake\":%llu,"
            "\"stake_mxd\":%.8f,"
            "\"rank\":%u,"
            "\"rank_score\":%u,"
            "\"active\":%d,"
            "\"in_rapid_table\":%d,"
            "\"rapid_table_position\":%u,"
            "\"metrics\":{"
            "\"avg_response_time\":%llu,"
            "\"min_response_time\":%llu,"
            "\"max_response_time\":%llu,"
            "\"response_count\":%u,"
            "\"message_success\":%u,"
            "\"message_total\":%u,"
            "\"reliability_score\":%.6f,"
            "\"performance_score\":%.6f,"
            "\"last_update\":%llu,"
            "\"tip_share\":%llu,"
            "\"peer_count\":%zu"
            "}}",
            i > 0 ? "," : "",
            i,
            node->node_id,
            addr_hex,
            (unsigned long long)node->stake_amount,
            stake_mxd,
            node->rapid_table_position,
            node->rank,
            node->active,
            node->in_rapid_table,
            node->rapid_table_position,
            (unsigned long long)node->metrics.avg_response_time,
            (unsigned long long)node->metrics.min_response_time,
            (unsigned long long)node->metrics.max_response_time,
            node->metrics.response_count,
            node->metrics.message_success,
            node->metrics.message_total,
            node->metrics.reliability_score,
            node->metrics.performance_score,
            (unsigned long long)node->metrics.last_update,
            (unsigned long long)node->metrics.tip_share,
            node->metrics.peer_count);
    }

    snprintf(response + offset, buf_size - offset, "]}");
    return response;
}

// Handle POST /wallet/generate endpoint - generate new wallet
static char* handle_wallet_generate(int *status_code) {
    *status_code = MHD_HTTP_OK;

    // Generate passphrase
    char passphrase[256] = {0};
    if (mxd_generate_passphrase(passphrase, sizeof(passphrase)) != 0) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to generate passphrase\"}");
    }

    // Generate keypair using Ed25519
    uint8_t public_key[32];
    uint8_t private_key[64];
    if (mxd_sig_keygen(MXD_SIGALG_ED25519, public_key, private_key) != 0) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to generate keypair\"}");
    }

    // Generate address from public key
    char address[64] = {0};
    if (mxd_address_to_string(MXD_SIGALG_ED25519, public_key, 32, /*mainnet*/1, address, sizeof(address)) != 0) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to generate address\"}");
    }

    // SECURITY FIX (C-06): Zero private key immediately - never include in response.
    // Users recover their keypair from the passphrase using mxd_generate_keypair_from_passphrase().
    sodium_memzero(private_key, sizeof(private_key));

    // Convert public key to hex
    char pubkey_hex[65] = {0};
    for (int i = 0; i < 32; i++) {
        snprintf(pubkey_hex + i*2, 3, "%02x", public_key[i]);
    }

    // Build response - SECURITY: passphrase + public info only, no private key
    char *response = malloc(1024);
    if (!response) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    // M-6: address20 field removed (was a 20-byte slice of addr32, no real consumer).
    // Wallet clients use the Base58Check `address` field as canonical identity.
    snprintf(response, 1024,
        "{"
        "\"passphrase\":\"%s\","
        "\"address\":\"mx%s\","
        "\"public_key\":\"%s\","
        "\"algo\":\"ed25519\","
        "\"algo_id\":1"
        "}",
        passphrase, address, pubkey_hex);

    MXD_LOG_INFO("http_api", "Generated new wallet: mx%s", address);
    return response;
}

// Handle GET /balance/{address} endpoint
static char* handle_balance(const char *address_hex, int *status_code) {
    *status_code = MHD_HTTP_OK;

    uint8_t address[MXD_ADDR32_LEN];
    if (hex_to_bytes(address_hex, address, MXD_ADDR32_LEN) != MXD_ADDR32_LEN) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid address format (expected 64 hex chars)\"}");
    }
    
    mxd_utxo_t *utxos = NULL;
    size_t utxo_count = 0;
    mxd_amount_t balance = 0;
    size_t spent_count = 0;
    size_t unspent_count = 0;

    if (mxd_get_utxos_by_pubkey_hash(address, &utxos, &utxo_count) == 0) {
        for (size_t i = 0; i < utxo_count; i++) {
            if (!utxos[i].is_spent) {
                balance += utxos[i].amount;
                unspent_count++;
            } else {
                spent_count++;
            }
        }
        for (size_t i = 0; i < utxo_count; i++) {
            mxd_free_utxo(&utxos[i]);
        }
        free(utxos);
    }

    // Also get authoritative UTXO stats
    size_t total_utxo_count = 0, pruned_utxo_count = 0;
    mxd_amount_t utxo_total_value = 0;
    mxd_get_utxo_stats(&total_utxo_count, &pruned_utxo_count, &utxo_total_value);

    char *response = malloc(512);
    snprintf(response, 512, "{\"address\":\"%s\",\"balance\":%llu,\"balance_mxd\":%.8f,"
             "\"utxo_count\":%zu,\"spent_count\":%zu,\"unspent_count\":%zu,"
             "\"db_total_utxos\":%zu,\"db_spent_utxos\":%zu,\"db_total_supply\":%llu}",
             address_hex, (unsigned long long)balance, (double)balance / 100000000.0,
             utxo_count, spent_count, unspent_count,
             total_utxo_count, pruned_utxo_count, (unsigned long long)utxo_total_value);
    return response;
}

// Handle POST /contract/deploy - Deploy a new smart contract
static char* handle_contract_deploy(const char *post_data, int *status_code) {
    *status_code = MHD_HTTP_OK;

    if (!post_data) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"No POST data provided\"}");
    }

    // Parse JSON input
    cJSON *json = cJSON_Parse(post_data);
    if (!json) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid JSON\"}");
    }

    // Extract code (hex string)
    cJSON *code_item = cJSON_GetObjectItem(json, "code");
    if (!code_item || !cJSON_IsString(code_item)) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Missing or invalid 'code' field (hex string required)\"}");
    }

    const char *code_hex = code_item->valuestring;
    size_t code_len = strlen(code_hex);
    if (code_len % 2 != 0 || code_len > MXD_MAX_CONTRACT_SIZE * 2) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid code length or exceeds maximum size\"}");
    }

    // Convert hex to bytes
    uint8_t *code = malloc(code_len / 2);
    if (!code) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    if (hex_to_bytes(code_hex, code, code_len / 2) != (int)(code_len / 2)) {
        free(code);
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid hex encoding\"}");
    }

    // Extract deployer address (optional, defaults to zeros if not provided)
    uint8_t deployer[20] = {0};
    cJSON *deployer_item = cJSON_GetObjectItem(json, "deployer");
    if (deployer_item && cJSON_IsString(deployer_item)) {
        const char *deployer_hex = deployer_item->valuestring;
        if (strlen(deployer_hex) == 40) {
            // SECURITY FIX: Check hex_to_bytes return value
            if (hex_to_bytes(deployer_hex, deployer, 20) != 20) {
                free(code);
                cJSON_Delete(json);
                *status_code = MHD_HTTP_BAD_REQUEST;
                return strdup("{\"error\":\"Invalid deployer address hex encoding\"}");
            }
        }
    }

    // Deploy contract
    mxd_contract_state_t state;
    int result = mxd_deploy_contract(code, code_len / 2, deployer, &state);
    free(code);
    cJSON_Delete(json);

    if (result != 0) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Contract deployment failed\",\"details\":\"Check node logs for details\"}");
    }

    // Convert contract hash to hex
    char hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) {
        snprintf(hash_hex + i*2, 3, "%02x", state.contract_hash[i]);
    }

    // Build success response
    char *response = malloc(512);
    snprintf(response, 512,
        "{\"success\":true,\"contract_hash\":\"%s\",\"gas_used\":%llu}",
        hash_hex, (unsigned long long)state.gas_used);

    return response;
}

// Handle POST /contract/call - Call a contract function
static char* handle_contract_call(const char *post_data, int *status_code) {
    *status_code = MHD_HTTP_OK;

    if (!post_data) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"No POST data provided\"}");
    }

    // Parse JSON input
    cJSON *json = cJSON_Parse(post_data);
    if (!json) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid JSON\"}");
    }

    // Extract contract_hash (hex string)
    cJSON *hash_item = cJSON_GetObjectItem(json, "contract_hash");
    if (!hash_item || !cJSON_IsString(hash_item)) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Missing or invalid 'contract_hash' field\"}");
    }

    const char *hash_hex = hash_item->valuestring;
    uint8_t contract_hash[64];
    if (hex_to_bytes(hash_hex, contract_hash, 64) != 64) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid contract_hash format (expected 128 hex chars)\"}");
    }

    // Extract function name
    cJSON *function_item = cJSON_GetObjectItem(json, "function");
    if (!function_item || !cJSON_IsString(function_item)) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Missing or invalid 'function' field\"}");
    }

    // Copy function name before freeing JSON
    char *function_name = strdup(function_item->valuestring);
    if (!function_name) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }

    // Extract params (optional, hex string)
    const char *params_hex = "";
    cJSON *params_item = cJSON_GetObjectItem(json, "params");
    if (params_item && cJSON_IsString(params_item)) {
        params_hex = params_item->valuestring;
    }

    // Convert params to bytes
    size_t params_len = strlen(params_hex);
    uint8_t *params = NULL;
    if (params_len > 0) {
        // SECURITY FIX: Limit params size to prevent DoS (1MB max = 2MB hex)
        if (params_len > MXD_MAX_CONTRACT_SIZE * 2) {
            free(function_name);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_BAD_REQUEST;
            return strdup("{\"error\":\"Params too large (max 1MB)\"}");
        }

        if (params_len % 2 != 0) {
            free(function_name);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_BAD_REQUEST;
            return strdup("{\"error\":\"Invalid params hex encoding\"}");
        }
        params = malloc(params_len / 2);
        if (!params) {
            free(function_name);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
            return strdup("{\"error\":\"Memory allocation failed\"}");
        }
        if (hex_to_bytes(params_hex, params, params_len / 2) != (int)(params_len / 2)) {
            free(function_name);
            free(params);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_BAD_REQUEST;
            return strdup("{\"error\":\"Invalid params hex encoding\"}");
        }
        params_len /= 2;
    }

    cJSON_Delete(json);

    // Load contract metadata from database
    mxd_contract_metadata_t contract_metadata;
    memset(&contract_metadata, 0, sizeof(contract_metadata));

    if (mxd_contracts_db_load_contract(contract_hash, &contract_metadata) != 0) {
        free(function_name);
        if (params) free(params);
        *status_code = MHD_HTTP_NOT_FOUND;
        return strdup("{\"error\":\"Contract not found in database\"}");
    }

    // Use existing deploy function to properly initialize the state
    mxd_contract_state_t state;
    memset(&state, 0, sizeof(state));

    // Smart contracts use legacy HASH160-style 20-byte deployer addresses (audit I-2);
    // not part of the addr32 cascade. Pass zero deployer for ad-hoc execution context.
    uint8_t zero_address[20] = {0};
    if (mxd_deploy_contract(contract_metadata.bytecode, contract_metadata.bytecode_size,
                           zero_address, &state) != 0) {
        free(function_name);
        free(contract_metadata.bytecode);
        if (params) free(params);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to initialize contract runtime\"}");
    }

    // Free contract metadata bytecode (state has its own copy)
    free(contract_metadata.bytecode);

    // Find the requested function
    IM3Runtime runtime = (IM3Runtime)state.runtime;
    IM3Function func;
    M3Result result = m3_FindFunction(&func, runtime, function_name);
    if (result) {
        free(function_name);
        if (params) free(params);
        mxd_free_contract_state(&state);

        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg),
                "{\"error\":\"Function not found\",\"function\":\"%s\",\"details\":\"%s\"}",
                function_name, result);
        *status_code = MHD_HTTP_NOT_FOUND;
        return strdup(error_msg);
    }

    // Function name no longer needed after finding function
    free(function_name);

    // Calculate gas cost
    uint64_t gas_used = mxd_calculate_gas_from_bytecode(state.bytecode, state.bytecode_size);
    if (gas_used == 0) {
        gas_used = 1000 + (state.bytecode_size / 10) + (params_len * 2);
    }

    // Execute function based on parameters
    uint32_t ret = 0;

    if (params_len == 0) {
        // No parameters
        result = m3_CallV(func);
    } else if (params_len == 4) {
        // One i32 parameter
        uint32_t param1;
        memcpy(&param1, params, 4);
        result = m3_CallV(func, param1);
    } else if (params_len == 8) {
        // Two i32 parameters
        uint32_t param1, param2;
        memcpy(&param1, params, 4);
        memcpy(&param2, params + 4, 4);
        result = m3_CallV(func, param1, param2);
    } else {
        if (params) free(params);
        mxd_free_contract_state(&state);

        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Unsupported parameter size (must be 0, 4, or 8 bytes for i32 functions)\"}");
    }

    if (params) free(params);

    if (result) {
        mxd_free_contract_state(&state);

        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg),
                "{\"error\":\"Contract execution failed\",\"details\":\"%s\"}", result);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup(error_msg);
    }

    // Get result
    result = m3_GetResultsV(func, &ret);
    if (result) {
        mxd_free_contract_state(&state);

        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg),
                "{\"error\":\"Failed to get function result\",\"details\":\"%s\"}", result);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup(error_msg);
    }

    // Build JSON response
    cJSON *response = cJSON_CreateObject();
    cJSON_AddBoolToObject(response, "success", 1);
    cJSON_AddNumberToObject(response, "result", ret);
    cJSON_AddNumberToObject(response, "gas_used", gas_used);

    // Convert result to hex
    char result_hex[9] = {0};
    snprintf(result_hex, sizeof(result_hex), "%08x", ret);
    cJSON_AddStringToObject(response, "result_hex", result_hex);

    char *response_str = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);

    // Cleanup
    mxd_free_contract_state(&state);

    *status_code = MHD_HTTP_OK;
    return response_str;
}

// Handle GET /contracts - List all deployed contracts
static char* handle_contracts_list(int *status_code) {
    *status_code = MHD_HTTP_OK;

    // Query database for all contracts
    mxd_contract_metadata_t *contracts = NULL;
    uint32_t count = 0;

    if (mxd_contracts_db_get_all_contracts(&contracts, &count) != 0) {
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to query contracts database\"}");
    }

    // Build JSON response
    cJSON *root = cJSON_CreateObject();
    cJSON *contracts_array = cJSON_CreateArray();

    for (uint32_t i = 0; i < count; i++) {
        cJSON *contract_obj = cJSON_CreateObject();

        // Convert hash to hex
        char hash_hex[129] = {0};
        for (int j = 0; j < 64; j++) {
            snprintf(hash_hex + j*2, 3, "%02x", contracts[i].contract_hash[j]);
        }
        cJSON_AddStringToObject(contract_obj, "hash", hash_hex);

        // Convert deployer to hex
        char deployer_hex[41] = {0};
        for (int j = 0; j < 20; j++) {
            snprintf(deployer_hex + j*2, 3, "%02x", contracts[i].deployer[j]);
        }
        cJSON_AddStringToObject(contract_obj, "deployer", deployer_hex);

        cJSON_AddNumberToObject(contract_obj, "deployed_at", contracts[i].deployed_at);
        cJSON_AddNumberToObject(contract_obj, "deployed_timestamp", contracts[i].deployed_timestamp);
        cJSON_AddNumberToObject(contract_obj, "bytecode_size", contracts[i].bytecode_size);
        cJSON_AddNumberToObject(contract_obj, "total_gas_used", contracts[i].total_gas_used);
        cJSON_AddNumberToObject(contract_obj, "call_count", contracts[i].call_count);

        cJSON_AddItemToArray(contracts_array, contract_obj);

        // Free bytecode if allocated
        if (contracts[i].bytecode) {
            free(contracts[i].bytecode);
        }
    }

    cJSON_AddItemToObject(root, "contracts", contracts_array);
    cJSON_AddNumberToObject(root, "count", count);

    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    // Free contracts array
    if (contracts) {
        free(contracts);
    }

    return json_str;
}

// Handle GET /contract/{hash} - Get contract info
static char* handle_contract_info(const char *hash_hex, int *status_code) {
    *status_code = MHD_HTTP_OK;

    if (strlen(hash_hex) != 128) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid contract hash (expected 128 hex chars)\"}");
    }

    uint8_t contract_hash[64];
    if (hex_to_bytes(hash_hex, contract_hash, 64) != 64) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid contract hash format\"}");
    }

    // TODO: Query database for contract info
    // For now, return not found

    *status_code = MHD_HTTP_NOT_FOUND;
    return strdup("{\"error\":\"Contract not found\",\"note\":\"Contract storage not yet implemented\"}");
}

// Handle GET /contract/{hash}/state - Get contract state
static char* handle_contract_state(const char *hash_hex, int *status_code) {
    *status_code = MHD_HTTP_OK;

    if (strlen(hash_hex) != 128) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid contract hash (expected 128 hex chars)\"}");
    }

    uint8_t contract_hash[64];
    if (hex_to_bytes(hash_hex, contract_hash, 64) != 64) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid contract hash format\"}");
    }

    // TODO: Query database for contract state
    // For now, return not found

    *status_code = MHD_HTTP_NOT_FOUND;
    return strdup("{\"error\":\"Contract not found\",\"note\":\"Contract storage not yet implemented\"}");
}

// Handle POST /bridge/submit endpoint - oracle submits a bridge mint request
// Required fields: type, bridge_contract, source_chain_id, source_tx_hash,
//                  source_block_number, recipient, amount, proof,
//                  oracle_pubkey (hex), oracle_algo_id, oracle_signature (hex)
char* handle_bridge_submit(const char *post_data, int *status_code) {
    *status_code = MHD_HTTP_OK;

    if (!post_data || strlen(post_data) == 0) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Empty request body\"}");
    }

    cJSON *json = cJSON_Parse(post_data);
    if (!json) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid JSON\"}");
    }

    // Validate "type" field
    cJSON *type_field = cJSON_GetObjectItem(json, "type");
    if (!type_field || !cJSON_IsString(type_field) ||
        strcmp(type_field->valuestring, "bridge_mint") != 0) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid or missing 'type' (expected 'bridge_mint')\"}");
    }

    // Extract required fields
    cJSON *bridge_contract = cJSON_GetObjectItem(json, "bridge_contract");
    cJSON *source_chain_id = cJSON_GetObjectItem(json, "source_chain_id");
    cJSON *source_tx_hash  = cJSON_GetObjectItem(json, "source_tx_hash");
    cJSON *source_block_num = cJSON_GetObjectItem(json, "source_block_number");
    cJSON *recipient       = cJSON_GetObjectItem(json, "recipient");
    cJSON *amount_field    = cJSON_GetObjectItem(json, "amount");

    // q.1 hard cutover: require oracles[] array, reject pre-q.1 singular fields.
    cJSON *oracles_field = cJSON_GetObjectItem(json, "oracles");
    cJSON *legacy_pubkey = cJSON_GetObjectItem(json, "oracle_pubkey");
    cJSON *legacy_sig    = cJSON_GetObjectItem(json, "oracle_signature");

    if (legacy_pubkey || legacy_sig) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Pre-q.1 singular oracle_pubkey/oracle_signature "
                      "fields are no longer accepted. Submit oracles: [{pubkey, "
                      "algo_id, signature}, ...] array with at least the on-chain "
                      "K-of-N threshold of attestations.\"}");
    }

    if (!bridge_contract || !cJSON_IsString(bridge_contract) ||
        !source_chain_id || !cJSON_IsString(source_chain_id) ||
        !source_tx_hash  || !cJSON_IsString(source_tx_hash) ||
        !source_block_num || !cJSON_IsNumber(source_block_num) ||
        !recipient       || !cJSON_IsString(recipient) ||
        !amount_field    || !cJSON_IsNumber(amount_field) ||
        !oracles_field   || !cJSON_IsArray(oracles_field)) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Missing or invalid required fields "
                      "(including oracles[] array)\"}");
    }

    int oracles_array_size = cJSON_GetArraySize(oracles_field);
    if (oracles_array_size <= 0 || oracles_array_size > MXD_MAX_BRIDGE_ORACLE_SIGS) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"oracles[] must contain 1..MXD_MAX_BRIDGE_ORACLE_SIGS entries\"}");
    }

    // Parse bridge contract hash (64 bytes = 128 hex chars)
    mxd_bridge_payload_t payload;
    memset(&payload, 0, sizeof(payload));
    payload.oracle_pubkey = NULL;
    payload.oracle_signature = NULL;

    if (hex_to_bytes(bridge_contract->valuestring, payload.bridge_contract, 64) != 64) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid bridge_contract (expected 128 hex chars)\"}");
    }

    // Parse source_chain_id string → uint32 stored in first 4 bytes
    // Expected format: "bsc_testnet_97" or "bsc_mainnet_56"
    {
        const char *chain_str = source_chain_id->valuestring;
        uint32_t chain_id = 0;
        if (strcmp(chain_str, "bsc_testnet_97") == 0) {
            chain_id = 97;
        } else if (strcmp(chain_str, "bsc_mainnet_56") == 0) {
            chain_id = 56;
        } else {
            cJSON_Delete(json);
            *status_code = MHD_HTTP_BAD_REQUEST;
            return strdup("{\"error\":\"Unsupported source_chain_id\"}");
        }
        // v7: store source_chain_id as big-endian u32 in first 4 bytes of the
        // 32-byte field, consistent with MXD-04 §3 "BE everywhere" and the
        // MXD-API-01 §6 canonical signing message.
        memset(payload.source_chain_id, 0, 32);
        uint32_t chain_id_be = htonl(chain_id);
        memcpy(payload.source_chain_id, &chain_id_be, sizeof(uint32_t));
    }

    // Parse source_tx_hash (32 bytes = 64 hex chars)
    if (hex_to_bytes(source_tx_hash->valuestring, payload.source_tx_hash, 32) != 32) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid source_tx_hash (expected 64 hex chars)\"}");
    }

    payload.source_block_number = (uint64_t)source_block_num->valuedouble;

    // Parse recipient MXD address (32 bytes = 64 hex chars per MXD-01 v1.1.x addr32)
    // TODO: mxd-bridge-oracle must emit 64-hex recipient — update after deploy
    if (hex_to_bytes(recipient->valuestring, payload.recipient_addr, MXD_ADDR32_LEN) != MXD_ADDR32_LEN) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid recipient (expected 64 hex chars)\"}");
    }

    payload.amount = (mxd_amount_t)amount_field->valuedouble;
    if (payload.amount == 0) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Amount must be > 0\"}");
    }

    // Inject MXD chain ID into payload (prevents cross-chain replay on reset)
    if (mxd_get_chain_id(payload.mxd_chain_id) != 0) {
        MXD_LOG_WARN("http_api", "Could not derive chain ID, using zero");
        memset(payload.mxd_chain_id, 0, 32);
    }

    // q.1 N-of-M oracle attestations.
    //
    // Each entry in oracles[] is { "pubkey": "<hex>", "algo_id": <int>,
    //                              "signature": "<hex>" }. We parse + populate
    // payload.oracles[i], then delegate cryptographic verification +
    // allowlist + K-of-N threshold to mxd_verify_bridge_oracle_signature
    // (single source of truth — same function block validation calls during
    // sync, so the HTTP and on-chain paths cannot diverge).
    //
    // Canonical 220-byte message layout (built inside the verifier):
    //   "MXD-BRG-V1\0" (11) || algo_id (1) ||
    //   bridge_contract(64) || source_chain_id(32, first 4 bytes BE u32) ||
    //   source_tx_hash(32) || source_block_number(8 BE) ||
    //   recipient(32 = MXD_ADDR32_LEN) || amount(8 BE) || mxd_chain_id(32)
    // See MXD-API-01 §6.
    for (int i = 0; i < oracles_array_size; i++) {
        cJSON *entry = cJSON_GetArrayItem(oracles_field, i);
        if (!entry || !cJSON_IsObject(entry)) {
            mxd_free_bridge_payload(&payload);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_BAD_REQUEST;
            return strdup("{\"error\":\"oracles[i] must be an object\"}");
        }

        cJSON *pk_field   = cJSON_GetObjectItem(entry, "pubkey");
        cJSON *algo_field = cJSON_GetObjectItem(entry, "algo_id");
        cJSON *sig_field  = cJSON_GetObjectItem(entry, "signature");
        if (!pk_field || !cJSON_IsString(pk_field) ||
            !algo_field || !cJSON_IsNumber(algo_field) ||
            !sig_field || !cJSON_IsString(sig_field)) {
            mxd_free_bridge_payload(&payload);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_BAD_REQUEST;
            return strdup("{\"error\":\"oracles[i] must contain pubkey (hex), "
                          "algo_id (int), signature (hex)\"}");
        }

        uint8_t oracle_algo_id = (uint8_t)algo_field->valueint;

        // Parse pubkey hex into a heap buffer (variable size: 32 Ed25519, 2592 Dilithium5)
        uint8_t pk_buf[2592];
        int pk_len = hex_to_bytes(pk_field->valuestring, pk_buf, sizeof(pk_buf));
        if (pk_len <= 0) {
            mxd_free_bridge_payload(&payload);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_BAD_REQUEST;
            return strdup("{\"error\":\"oracles[i].pubkey hex parse failed\"}");
        }

        uint8_t sig_buf[4627];
        int sig_len = hex_to_bytes(sig_field->valuestring, sig_buf, sizeof(sig_buf));
        if (sig_len <= 0) {
            mxd_free_bridge_payload(&payload);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_BAD_REQUEST;
            return strdup("{\"error\":\"oracles[i].signature hex parse failed\"}");
        }

        payload.oracles[i].algo_id = oracle_algo_id;
        payload.oracles[i].pubkey_length = (uint16_t)pk_len;
        payload.oracles[i].pubkey = malloc((size_t)pk_len);
        payload.oracles[i].sig_length = (uint16_t)sig_len;
        payload.oracles[i].signature = malloc((size_t)sig_len);
        if (!payload.oracles[i].pubkey || !payload.oracles[i].signature) {
            // Bump oracle_count first so mxd_free_bridge_payload's iteration
            // covers the partially-populated entry (whichever of the two
            // mallocs succeeded). mxd_free_bridge_payload is null-safe per
            // slot, so this is correct even with one allocation having failed.
            payload.oracle_count = (uint32_t)(i + 1);
            mxd_free_bridge_payload(&payload);
            cJSON_Delete(json);
            *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
            return strdup("{\"error\":\"Memory allocation failed\"}");
        }
        memcpy(payload.oracles[i].pubkey, pk_buf, (size_t)pk_len);
        memcpy(payload.oracles[i].signature, sig_buf, (size_t)sig_len);
        // Entry fully populated — advance oracle_count so any later error
        // path can clean it up.
        payload.oracle_count = (uint32_t)(i + 1);
    }

    // Verify K-of-N: allowlist check, duplicate-signer check, per-sig
    // cryptographic verification, threshold enforcement — all in
    // mxd_verify_bridge_oracle_signature. Reject the submission here on any
    // failure so the same payload that block validation would reject doesn't
    // sit on the queue.
    if (mxd_verify_bridge_oracle_signature(&payload) != 0) {
        mxd_free_bridge_payload(&payload);
        cJSON_Delete(json);
        *status_code = MHD_HTTP_FORBIDDEN;
        return strdup("{\"error\":\"Oracle attestation verification failed "
                      "(see node logs for which check rejected the submission: "
                      "allowlist, duplicate signer, signature, or below threshold)\"}");
    }

    cJSON_Delete(json);

    // Step 2: Check bridge contract authorization
    if (!mxd_is_bridge_contract_authorized(payload.bridge_contract)) {
        mxd_free_bridge_payload(&payload);
        *status_code = MHD_HTTP_FORBIDDEN;
        return strdup("{\"error\":\"Bridge contract not authorized\"}");
    }

    // Step 3: Check replay protection (first-pass on receiving node)
    if (mxd_is_bridge_tx_processed(payload.source_tx_hash)) {
        mxd_free_bridge_payload(&payload);
        *status_code = MHD_HTTP_CONFLICT;
        return strdup("{\"error\":\"Source transaction already processed\"}");
    }

    // Step 4: Create v3 bridge mint transaction with oracle attestation.
    // Unlike the old v2 coinbase approach, this transaction carries the oracle's
    // signature so every node in the network can independently verify it.
    mxd_transaction_v3_t bridge_tx;
    if (mxd_create_bridge_mint_tx(&bridge_tx, &payload) != 0) {
        mxd_free_bridge_payload(&payload);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to create bridge mint transaction\"}");
    }

    // Calculate transaction hash (commits to oracle credentials)
    if (mxd_calculate_tx_hash_v3(&bridge_tx, bridge_tx.tx_hash) != 0) {
        mxd_free_transaction_v3(&bridge_tx);
        mxd_free_bridge_payload(&payload);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to calculate transaction hash\"}");
    }

    // Step 5: Queue for block inclusion (NOT mempool — v3 bridge transactions
    // use the dedicated bridge queue picked up by the block proposer)
    if (mxd_queue_bridge_mint(&bridge_tx) != 0) {
        mxd_free_transaction_v3(&bridge_tx);
        mxd_free_bridge_payload(&payload);
        *status_code = MHD_HTTP_SERVICE_UNAVAILABLE;
        return strdup("{\"error\":\"Bridge queue full, try again later\"}");
    }

    // NOTE: Do NOT mark as processed here. Replay protection is applied during
    // block validation on ALL nodes (in mxd_apply_block_transactions).

    // Record mint for daily rate tracking
    mxd_record_bridge_mint(payload.amount);

    // Build success response
    char tx_hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) {
        snprintf(tx_hash_hex + i*2, 3, "%02x", bridge_tx.tx_hash[i]);
    }

    char *response = malloc(256);
    snprintf(response, 256,
        "{\"success\":true,\"tx_hash\":\"%s\",\"pending_count\":%zu}",
        tx_hash_hex, mxd_pending_bridge_count());

    // Save values before freeing
    mxd_amount_t log_amount = payload.amount;
    uint8_t log_r0 = payload.recipient_addr[0];
    uint8_t log_r1 = payload.recipient_addr[1];

    mxd_free_transaction_v3(&bridge_tx);
    mxd_free_bridge_payload(&payload);

    MXD_LOG_INFO("http_api", "Bridge mint v3 queued: %s (amount: %llu, recipient: %02x%02x...)",
                 tx_hash_hex, (unsigned long long)log_amount, log_r0, log_r1);
    return response;
}

// Handle POST /admin/submit — submit a pre-signed admin transaction (bridge
// authorize/revoke or oracle set update). The body must contain a hex-
// encoded serialized admin transaction carrying 3-of-5 oracle signatures
// over the canonical admin message. Node validates sigs against the
// currently authorized oracle set (on-chain or config), checks
// nonce-freshness, and queues for block inclusion.
char* handle_admin_submit(const char *post_data, int *status_code) {
    *status_code = MHD_HTTP_OK;

    if (!post_data || strlen(post_data) == 0) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Empty request body\"}");
    }
    cJSON *json = cJSON_Parse(post_data);
    if (!json) {
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid JSON\"}");
    }
    cJSON *signed_tx_hex = cJSON_GetObjectItem(json, "signed_tx");
    if (!signed_tx_hex || !cJSON_IsString(signed_tx_hex)) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Missing required field: signed_tx (hex-encoded serialized admin tx)\"}");
    }
    const char *hex_str = signed_tx_hex->valuestring;
    size_t hex_len = strlen(hex_str);
    if (hex_len < 2 || hex_len % 2 != 0 || hex_len > 2 * 131072) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid signed_tx hex length\"}");
    }
    size_t tx_data_len = hex_len / 2;
    uint8_t *tx_data = malloc(tx_data_len);
    if (!tx_data) {
        cJSON_Delete(json);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Memory allocation failed\"}");
    }
    if (hex_to_bytes(hex_str, tx_data, tx_data_len) != (int)tx_data_len) {
        free(tx_data);
        cJSON_Delete(json);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Invalid hex encoding in signed_tx\"}");
    }
    cJSON_Delete(json);

    // Deserialize as v3 tx — the dispatcher handles admin payload types.
    mxd_transaction_v3_t tx;
    memset(&tx, 0, sizeof(tx));
    if (mxd_deserialize_transaction_v3_from_block(tx_data, tx_data_len, &tx) != 0) {
        free(tx_data);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Failed to deserialize admin transaction\"}");
    }

    if (tx.type != MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE &&
        tx.type != MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE &&
        tx.type != MXD_TX_TYPE_ADMIN_UPDATE_ORACLE_SET) {
        mxd_free_transaction_v3(&tx);
        free(tx_data);
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Not an admin transaction type\"}");
    }

    // Recompute tx_hash from content — the submitter tool leaves the wire's
    // tx_hash as a zero placeholder (it can't know the final hash locally).
    // Matches the bridge-mint path in handle_bridge_submit.
    if (mxd_calculate_tx_hash_v3(&tx, tx.tx_hash) != 0) {
        mxd_free_transaction_v3(&tx);
        free(tx_data);
        *status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
        return strdup("{\"error\":\"Failed to compute admin tx hash\"}");
    }

    // Full validation — structure + 3-of-5 oracle sigs + nonce freshness.
    if (mxd_validate_admin_tx(&tx) != 0) {
        mxd_free_transaction_v3(&tx);
        free(tx_data);
        MXD_LOG_ERROR("http_api", "Admin tx validation failed");
        *status_code = MHD_HTTP_BAD_REQUEST;
        return strdup("{\"error\":\"Admin transaction validation failed "
                      "(check 3-of-5 oracle signatures, nonce not reused, and payload shape)\"}");
    }

    // Queue for block inclusion.
    if (mxd_queue_admin_tx(&tx) != 0) {
        mxd_free_transaction_v3(&tx);
        free(tx_data);
        *status_code = MHD_HTTP_SERVICE_UNAVAILABLE;
        return strdup("{\"error\":\"Admin queue full, try again later\"}");
    }

    char tx_hash_hex[129] = {0};
    for (int i = 0; i < 64; i++) snprintf(tx_hash_hex + i*2, 3, "%02x", tx.tx_hash[i]);

    const char *type_name =
        tx.type == MXD_TX_TYPE_ADMIN_AUTHORIZE_BRIDGE ? "authorize_bridge" :
        tx.type == MXD_TX_TYPE_ADMIN_REVOKE_BRIDGE ? "revoke_bridge" :
        "update_oracle_set";

    MXD_LOG_INFO("http_api", "Admin tx queued: type=%s nonce=%lu",
                 type_name,
                 (unsigned long)tx.payload.admin->nonce);

    char *response = malloc(256);
    snprintf(response, 256,
             "{\"success\":true,\"tx_hash\":\"%s\",\"type\":\"%s\"}",
             tx_hash_hex, type_name);

    mxd_free_transaction_v3(&tx);
    free(tx_data);
    return response;
}

static enum MHD_Result handle_request(void *cls,
                                       struct MHD_Connection *connection,
                                       const char *url,
                                       const char *method,
                                       const char *version,
                                       const char *upload_data,
                                       size_t *upload_data_size,
                                       void **con_cls) {
    (void)cls;
    (void)version;
    
    // Handle POST data accumulation
    if (strcmp(method, "POST") == 0) {
        if (*con_cls == NULL) {
            // First call - allocate connection context
            connection_info_t *con_info = calloc(1, sizeof(connection_info_t));
            if (!con_info) return MHD_NO;
            *con_cls = con_info;
            return MHD_YES;
        }
        
        connection_info_t *con_info = *con_cls;
        
        if (*upload_data_size > 0) {
            // Limit POST body to 1 MB to prevent memory exhaustion
            if (con_info->post_data_size + *upload_data_size > 1048576) {
                return MHD_NO;
            }
            // Accumulate POST data
            char *new_data = realloc(con_info->post_data, con_info->post_data_size + *upload_data_size + 1);
            if (!new_data) return MHD_NO;
            memcpy(new_data + con_info->post_data_size, upload_data, *upload_data_size);
            con_info->post_data_size += *upload_data_size;
            new_data[con_info->post_data_size] = '\0';
            con_info->post_data = new_data;
            *upload_data_size = 0;
            return MHD_YES;
        }
        
        // All data received - process request
        char *json_response = NULL;
        int status_code = MHD_HTTP_OK;

        // SECURITY FIX (C-07): Require API key auth for all mutation endpoints
        if (!check_api_auth(connection)) {
            free(con_info->post_data);
            free(con_info);
            *con_cls = NULL;
            return send_json_error(connection, MHD_HTTP_UNAUTHORIZED,
                                   "Authentication required. Provide Authorization: Bearer <token>");
        }

        if (strcmp(url, "/transaction") == 0) {
            json_response = handle_transaction_submit(con_info->post_data, &status_code);
        }
        else if (strcmp(url, "/contract/deploy") == 0) {
            json_response = handle_contract_deploy(con_info->post_data, &status_code);
        }
        else if (strcmp(url, "/contract/call") == 0) {
            json_response = handle_contract_call(con_info->post_data, &status_code);
        }
        else if (strcmp(url, "/bridge/submit") == 0) {
            json_response = handle_bridge_submit(con_info->post_data, &status_code);
        }
        else if (strcmp(url, "/admin/submit") == 0) {
            json_response = handle_admin_submit(con_info->post_data, &status_code);
        }
        else if (strcmp(url, "/wallet/generate") == 0) {
            // Auth is already checked above for all POST endpoints
            json_response = handle_wallet_generate(&status_code);
        }
        else {
            json_response = strdup("{\"error\":\"Endpoint not found\"}");
            status_code = MHD_HTTP_NOT_FOUND;
        }
        
        // Clean up connection context
        free(con_info->post_data);
        free(con_info);
        *con_cls = NULL;
        
        struct MHD_Response *response = MHD_create_response_from_buffer(
            strlen(json_response), json_response, MHD_RESPMEM_MUST_FREE);
        MHD_add_response_header(response, "Content-Type", "application/json");
        MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
        enum MHD_Result ret = MHD_queue_response(connection, status_code, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    // Handle OPTIONS for CORS preflight
    if (strcmp(method, "OPTIONS") == 0) {
        struct MHD_Response *response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
        MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type, Authorization");
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    if (strcmp(method, "GET") != 0) {
        const char *error = "{\"error\":\"Method not allowed\"}";
        struct MHD_Response *response = MHD_create_response_from_buffer(
            strlen(error), (void*)error, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(response, "Content-Type", "application/json");
        MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
        enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_METHOD_NOT_ALLOWED, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    char *json_response = NULL;
    int status_code = MHD_HTTP_OK;
    
    // Handle /status endpoint
    if (strcmp(url, "/status") == 0 || strcmp(url, "/") == 0) {
        uint32_t height = 0;
        mxd_get_blockchain_height(&height);

        // Get latest block and calculate statistics
        char latest_hash[129] = {0};
        uint64_t total_transactions = 0;
        double avg_block_time = 0.0;
        double current_tps = 0.0;
        uint32_t validator_count = 0;
        uint32_t difficulty = 1;
        uint64_t total_supply = 0;

        // Get validator count from rapid table
        const mxd_rapid_table_t *table = mxd_get_rapid_table();
        if (table) {
            validator_count = (uint32_t)table->count;
        }

        if (height > 0) {
            // Get latest block for hash
            mxd_block_t block;
            if (mxd_retrieve_block_by_height(height - 1, &block) == 0) {
                for (int i = 0; i < 64; i++) {
                    snprintf(latest_hash + i*2, 3, "%02x", block.block_hash[i]);
                }
                difficulty = block.difficulty;
                total_supply = block.total_supply;
                mxd_free_block(&block);
            }

            // total_supply comes directly from the block — no fallback needed

            // Calculate stats from recent blocks (last 100 or all)
            uint32_t sample_size = (height > 100) ? 100 : height;
            uint64_t first_timestamp = 0;
            uint64_t last_timestamp = 0;
            uint32_t blocks_retrieved = 0;

            for (uint32_t i = 0; i < sample_size; i++) {
                uint32_t bh = height - 1 - i;
                mxd_block_t b = {0};
                if (mxd_retrieve_block_by_height(bh, &b) == 0) {
                    total_transactions += b.transaction_count;
                    if (blocks_retrieved == 0) last_timestamp = b.timestamp;
                    first_timestamp = b.timestamp;
                    blocks_retrieved++;
                    mxd_free_block(&b);
                }
                if (bh == 0) break;
            }

            // Average block time
            if (blocks_retrieved > 1 && last_timestamp > first_timestamp) {
                avg_block_time = (double)(last_timestamp - first_timestamp) / (double)(blocks_retrieved - 1);
            }

            // TPS
            if (blocks_retrieved > 1 && last_timestamp > first_timestamp) {
                uint64_t time_span = last_timestamp - first_timestamp;
                if (time_span > 0) {
                    current_tps = (double)total_transactions / (double)time_span;
                }
            }
        } else {
            // Check for genesis block at height 0
            mxd_block_t block;
            if (mxd_retrieve_block_by_height(0, &block) == 0) {
                for (int i = 0; i < 64; i++) {
                    snprintf(latest_hash + i*2, 3, "%02x", block.block_hash[i]);
                }
                height = 1;
                total_supply = block.total_supply;
                total_transactions = block.transaction_count;
                mxd_free_block(&block);
            }
        }

        json_response = malloc(1024);
        if (json_response) {
            snprintf(json_response, 1024,
                "{\"status\":\"ok\","
                "\"height\":%u,"
                "\"latest_hash\":\"%s\","
                "\"total_transactions\":%llu,"
                "\"validator_count\":%u,"
                "\"difficulty\":%u,"
                "\"total_supply\":%llu,"
                "\"avg_block_time\":%.2f,"
                "\"current_tps\":%.4f}",
                height, latest_hash,
                (unsigned long long)total_transactions,
                validator_count, difficulty,
                (unsigned long long)total_supply,
                avg_block_time, current_tps);
        }
    }
    // Handle /block/{height} or /block/latest endpoint
    else if (strncmp(url, "/block/", 7) == 0) {
        const char *height_str = url + 7;
        uint32_t height;
        if (strcmp(height_str, "latest") == 0) {
            mxd_get_blockchain_height(&height);
            if (height > 0) height--;  // current_height is count, latest block is at count-1
        } else {
            char *endptr;
            unsigned long parsed = strtoul(height_str, &endptr, 10);
            if (*endptr != '\0' || parsed > UINT32_MAX) {
                json_response = strdup("{\"error\":\"Invalid block height\"}");
                status_code = MHD_HTTP_BAD_REQUEST;
                goto send_response;
            }
            height = (uint32_t)parsed;
        }

        mxd_block_t block;
        if (mxd_retrieve_block_by_height(height, &block) == 0) {
            json_response = block_to_json(&block);
            mxd_free_block(&block);
        } else {
            json_response = strdup("{\"error\":\"Block not found\"}");
            status_code = MHD_HTTP_NOT_FOUND;
        }
    }
    // Handle /balance/{address} endpoint
    else if (strncmp(url, "/balance/", 9) == 0) {
        const char *address_hex = url + 9;
        json_response = handle_balance(address_hex, &status_code);
    }
    // Handle /wallet/generate - reject GET requests; this endpoint must use POST
    else if (strcmp(url, "/wallet/generate") == 0) {
        return send_json_error(connection, MHD_HTTP_METHOD_NOT_ALLOWED,
                               "Use POST /wallet/generate instead of GET");
    }
    // Handle /chain_id endpoint - MXD chain identifier for bridge signing
    else if (strcmp(url, "/chain_id") == 0) {
        uint8_t chain_id[32];
        if (mxd_get_chain_id(chain_id) == 0) {
            char hex[65] = {0};
            for (int i = 0; i < 32; i++) snprintf(hex + i*2, 3, "%02x", chain_id[i]);
            json_response = malloc(128);
            snprintf(json_response, 128, "{\"chain_id\":\"%s\"}", hex);
        } else {
            json_response = strdup("{\"chain_id\":\"0000000000000000000000000000000000000000000000000000000000000000\"}");
        }
    }
    // Handle /validators endpoint
    else if (strcmp(url, "/validators") == 0) {
        json_response = handle_validators(&status_code);
    }
    // Handle /rsc endpoint - full rapid stake table
    else if (strcmp(url, "/rsc") == 0) {
        json_response = handle_rsc(&status_code);
    }
    // Handle /node/identity endpoint - for testing transactions
    else if (strcmp(url, "/node/identity") == 0) {
        json_response = handle_node_identity(&status_code);
    }
    // Handle /blocks/latest endpoint
    else if (strcmp(url, "/blocks/latest") == 0) {
        const char *limit_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "limit");
        int limit = limit_str ? atoi(limit_str) : 10;
        if (limit > 100) limit = 100;
        if (limit < 1) limit = 1;

        uint32_t height = 0;
        mxd_get_blockchain_height(&height);

        // Build JSON array of blocks
        size_t buf_size = (size_t)limit * 8192 + 256;  // 8KB per block (generous)
        json_response = malloc(buf_size);
        if (json_response) {
            size_t offset = 0;
            offset += snprintf(json_response + offset, buf_size - offset, "{\"blocks\":[");
            int first = 1;

            for (int i = 0; i < limit && height > 0; i++) {
                mxd_block_t block;
                if (mxd_retrieve_block_by_height(height - 1 - i, &block) == 0) {
                    char *block_json = block_to_json(&block);
                    if (block_json) {
                        offset += snprintf(json_response + offset, buf_size - offset,
                                           "%s%s", first ? "" : ",", block_json);
                        free(block_json);
                        first = 0;
                        if (offset >= buf_size - 10) {
                            mxd_free_block(&block);
                            break;
                        }
                    }
                    mxd_free_block(&block);
                }
            }

            snprintf(json_response + offset, buf_size - offset, "]}");
        }
    }
    // Handle /contracts endpoint - list all contracts
    else if (strcmp(url, "/contracts") == 0) {
        json_response = handle_contracts_list(&status_code);
    }
    // Handle /contract/{hash} endpoint - get contract info
    else if (strncmp(url, "/contract/", 10) == 0 && strlen(url) == 138) {
        const char *hash_hex = url + 10;
        // Check if it's a state query
        if (strlen(url) > 138 && strcmp(url + 138, "/state") == 0) {
            json_response = handle_contract_state(hash_hex, &status_code);
        } else {
            json_response = handle_contract_info(hash_hex, &status_code);
        }
    }
    // Handle /contract/{hash}/state endpoint
    else if (strncmp(url, "/contract/", 10) == 0 && strlen(url) > 138) {
        const char *remainder = url + 10;
        char hash_hex[129];
        strncpy(hash_hex, remainder, 128);
        hash_hex[128] = '\0';
        if (strcmp(remainder + 128, "/state") == 0) {
            json_response = handle_contract_state(hash_hex, &status_code);
        } else {
            json_response = strdup("{\"error\":\"Endpoint not found\"}");
            status_code = MHD_HTTP_NOT_FOUND;
        }
    }
    else {
        json_response = strdup("{\"error\":\"Endpoint not found\"}");
        status_code = MHD_HTTP_NOT_FOUND;
    }
    
send_response:
    if (!json_response) {
        json_response = strdup("{\"error\":\"Internal server error\"}");
        status_code = MHD_HTTP_INTERNAL_SERVER_ERROR;
    }

    struct MHD_Response *response = MHD_create_response_from_buffer(
        strlen(json_response), json_response, MHD_RESPMEM_MUST_FREE);
    MHD_add_response_header(response, "Content-Type", "application/json");
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");

    enum MHD_Result ret = MHD_queue_response(connection, status_code, response);
    MHD_destroy_response(response);

    return ret;
}

int mxd_http_api_start(uint16_t port) {
    if (http_daemon) {
        MXD_LOG_WARN("http_api", "HTTP API server already running");
        return 0;
    }
    
    http_daemon = MHD_start_daemon(
        MHD_USE_THREAD_PER_CONNECTION,
        port,
        NULL, NULL,
        &handle_request, NULL,
        MHD_OPTION_END);
    
    if (!http_daemon) {
        MXD_LOG_ERROR("http_api", "Failed to start HTTP API server on port %u", port);
        return -1;
    }
    
    MXD_LOG_INFO("http_api", "HTTP API server started on port %u", port);
    return 0;
}

void mxd_http_api_stop(void) {
    if (http_daemon) {
        MHD_stop_daemon(http_daemon);
        http_daemon = NULL;
        MXD_LOG_INFO("http_api", "HTTP API server stopped");
    }
}

int mxd_http_api_is_running(void) {
    return http_daemon != NULL;
}
