#ifndef MXD_MERKLE_TRIE_H
#define MXD_MERKLE_TRIE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

// Merkle Patricia Trie node types
typedef enum {
    MXD_TRIE_NODE_EMPTY = 0,
    MXD_TRIE_NODE_LEAF = 1,
    MXD_TRIE_NODE_BRANCH = 2,
    MXD_TRIE_NODE_EXTENSION = 3
} mxd_trie_node_type_t;

// Forward declaration
typedef struct mxd_trie_node mxd_trie_node_t;

// Merkle Patricia Trie node structure
struct mxd_trie_node {
    mxd_trie_node_type_t type;
    uint8_t hash[64];           // SHA-512 hash of this node
    int hash_valid;             // Whether hash is up to date
    
    union {
        // Leaf node: stores key suffix and value
        struct {
            uint8_t *key;
            size_t key_len;
            uint8_t *value;
            size_t value_len;
        } leaf;
        
        // Branch node: 16 children (for hex nibbles) + optional value
        struct {
            mxd_trie_node_t *children[16];
            uint8_t *value;
            size_t value_len;
        } branch;
        
        // Extension node: shared key prefix + child
        struct {
            uint8_t *key;
            size_t key_len;
            mxd_trie_node_t *child;
        } extension;
    } data;
};

// Merkle Patricia Trie structure
typedef struct {
    mxd_trie_node_t *root;
    size_t node_count;
    uint8_t root_hash[64];
    int root_hash_valid;
} mxd_merkle_trie_t;

/**
 * Create a new empty merkle patricia trie
 * @return Pointer to new trie, or NULL on failure
 */
mxd_merkle_trie_t *mxd_trie_create(void);

/**
 * Free a merkle patricia trie and all its nodes
 * @param trie Trie to free
 */
void mxd_trie_free(mxd_merkle_trie_t *trie);

/**
 * Insert or update a key-value pair in the trie
 * @param trie Trie to modify
 * @param key Key bytes
 * @param key_len Key length
 * @param value Value bytes
 * @param value_len Value length
 * @return 0 on success, -1 on failure
 */
int mxd_trie_set(mxd_merkle_trie_t *trie, const uint8_t *key, size_t key_len,
                 const uint8_t *value, size_t value_len);

/**
 * Get a value from the trie
 * @param trie Trie to query
 * @param key Key bytes
 * @param key_len Key length
 * @param value Buffer to store value (output)
 * @param value_len Pointer to value length (input: buffer size, output: actual size)
 * @return 0 on success, -1 if key not found or buffer too small
 */
int mxd_trie_get(const mxd_merkle_trie_t *trie, const uint8_t *key, size_t key_len,
                 uint8_t *value, size_t *value_len);

/**
 * Delete a key from the trie
 * @param trie Trie to modify
 * @param key Key bytes
 * @param key_len Key length
 * @return 0 on success, -1 if key not found
 */
int mxd_trie_delete(mxd_merkle_trie_t *trie, const uint8_t *key, size_t key_len);

/**
 * Calculate and return the merkle root hash of the trie
 * @param trie Trie to hash
 * @param root_hash Buffer to store root hash (64 bytes)
 * @return 0 on success, -1 on failure
 */
int mxd_trie_get_root_hash(mxd_merkle_trie_t *trie, uint8_t *root_hash);

/**
 * Verify the integrity of the trie by recalculating all hashes
 * @param trie Trie to verify
 * @return 0 if valid, -1 if invalid
 */
int mxd_trie_verify(mxd_merkle_trie_t *trie);

/**
 * Serialize the trie to a byte array for storage
 * @param trie Trie to serialize
 * @param buffer Output buffer (can be NULL to query size)
 * @param buffer_size Pointer to buffer size (input: available, output: required)
 * @return 0 on success, -1 on failure
 */
int mxd_trie_serialize(const mxd_merkle_trie_t *trie, uint8_t *buffer, size_t *buffer_size);

/**
 * Deserialize a trie from a byte array
 * @param buffer Input buffer
 * @param buffer_size Buffer size
 * @return Pointer to deserialized trie, or NULL on failure
 */
mxd_merkle_trie_t *mxd_trie_deserialize(const uint8_t *buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif // MXD_MERKLE_TRIE_H
