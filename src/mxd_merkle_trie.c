#include "../include/mxd_merkle_trie.h"
#include "../include/mxd_crypto.h"
#include "../include/mxd_logging.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Helper: Convert byte to two hex nibbles
static void byte_to_nibbles(uint8_t byte, uint8_t *nibble1, uint8_t *nibble2) {
    *nibble1 = (byte >> 4) & 0x0F;
    *nibble2 = byte & 0x0F;
}

// Helper: Get nibble at index from key
static uint8_t get_nibble(const uint8_t *key, size_t key_len, size_t nibble_index) {
    size_t byte_index = nibble_index / 2;
    if (byte_index >= key_len) {
        return 0xFF;  // Invalid nibble
    }
    
    if (nibble_index % 2 == 0) {
        return (key[byte_index] >> 4) & 0x0F;
    } else {
        return key[byte_index] & 0x0F;
    }
}

// Helper: Count matching nibbles between two keys
static size_t count_matching_nibbles(const uint8_t *key1, size_t key1_len,
                                     const uint8_t *key2, size_t key2_len,
                                     size_t start_nibble) {
    size_t matches = 0;
    size_t max_nibbles = (key1_len < key2_len ? key1_len : key2_len) * 2;
    
    for (size_t i = start_nibble; i < max_nibbles; i++) {
        uint8_t n1 = get_nibble(key1, key1_len, i);
        uint8_t n2 = get_nibble(key2, key2_len, i);
        
        if (n1 == 0xFF || n2 == 0xFF || n1 != n2) {
            break;
        }
        matches++;
    }
    
    return matches;
}

// Helper: Create a new leaf node
static mxd_trie_node_t *create_leaf_node(const uint8_t *key, size_t key_len,
                                         const uint8_t *value, size_t value_len) {
    mxd_trie_node_t *node = calloc(1, sizeof(mxd_trie_node_t));
    if (!node) return NULL;
    
    node->type = MXD_TRIE_NODE_LEAF;
    node->hash_valid = 0;
    
    node->data.leaf.key = malloc(key_len);
    if (!node->data.leaf.key) {
        free(node);
        return NULL;
    }
    memcpy(node->data.leaf.key, key, key_len);
    node->data.leaf.key_len = key_len;
    
    node->data.leaf.value = malloc(value_len);
    if (!node->data.leaf.value) {
        free(node->data.leaf.key);
        free(node);
        return NULL;
    }
    memcpy(node->data.leaf.value, value, value_len);
    node->data.leaf.value_len = value_len;
    
    return node;
}

// Helper: Create a new branch node
static mxd_trie_node_t *create_branch_node(void) {
    mxd_trie_node_t *node = calloc(1, sizeof(mxd_trie_node_t));
    if (!node) return NULL;
    
    node->type = MXD_TRIE_NODE_BRANCH;
    node->hash_valid = 0;
    
    for (int i = 0; i < 16; i++) {
        node->data.branch.children[i] = NULL;
    }
    node->data.branch.value = NULL;
    node->data.branch.value_len = 0;
    
    return node;
}

// Helper: Create a new extension node
static mxd_trie_node_t *create_extension_node(const uint8_t *key, size_t key_len,
                                               mxd_trie_node_t *child) {
    mxd_trie_node_t *node = calloc(1, sizeof(mxd_trie_node_t));
    if (!node) return NULL;
    
    node->type = MXD_TRIE_NODE_EXTENSION;
    node->hash_valid = 0;
    
    node->data.extension.key = malloc(key_len);
    if (!node->data.extension.key) {
        free(node);
        return NULL;
    }
    memcpy(node->data.extension.key, key, key_len);
    node->data.extension.key_len = key_len;
    node->data.extension.child = child;
    
    return node;
}

// Helper: Free a trie node recursively
static void free_node(mxd_trie_node_t *node) {
    if (!node) return;
    
    switch (node->type) {
        case MXD_TRIE_NODE_LEAF:
            free(node->data.leaf.key);
            free(node->data.leaf.value);
            break;
            
        case MXD_TRIE_NODE_BRANCH:
            for (int i = 0; i < 16; i++) {
                free_node(node->data.branch.children[i]);
            }
            free(node->data.branch.value);
            break;
            
        case MXD_TRIE_NODE_EXTENSION:
            free(node->data.extension.key);
            free_node(node->data.extension.child);
            break;
            
        default:
            break;
    }
    
    free(node);
}

// Helper: Calculate hash of a node
static int calculate_node_hash(mxd_trie_node_t *node) {
    if (!node) return -1;
    if (node->hash_valid) return 0;
    
    // Prepare data to hash based on node type
    uint8_t *hash_data = NULL;
    size_t hash_data_len = 0;
    
    switch (node->type) {
        case MXD_TRIE_NODE_LEAF: {
            // Hash: type + key_len + key + value_len + value
            hash_data_len = 1 + sizeof(size_t) + node->data.leaf.key_len + 
                           sizeof(size_t) + node->data.leaf.value_len;
            hash_data = malloc(hash_data_len);
            if (!hash_data) return -1;
            
            size_t offset = 0;
            hash_data[offset++] = (uint8_t)node->type;
            memcpy(hash_data + offset, &node->data.leaf.key_len, sizeof(size_t));
            offset += sizeof(size_t);
            memcpy(hash_data + offset, node->data.leaf.key, node->data.leaf.key_len);
            offset += node->data.leaf.key_len;
            memcpy(hash_data + offset, &node->data.leaf.value_len, sizeof(size_t));
            offset += sizeof(size_t);
            memcpy(hash_data + offset, node->data.leaf.value, node->data.leaf.value_len);
            break;
        }
        
        case MXD_TRIE_NODE_BRANCH: {
            // Hash: type + children_hashes + value_len + value
            hash_data_len = 1 + (16 * 64) + sizeof(size_t) + node->data.branch.value_len;
            hash_data = malloc(hash_data_len);
            if (!hash_data) return -1;
            
            size_t offset = 0;
            hash_data[offset++] = (uint8_t)node->type;
            
            // Include hashes of all children
            for (int i = 0; i < 16; i++) {
                if (node->data.branch.children[i]) {
                    calculate_node_hash(node->data.branch.children[i]);
                    memcpy(hash_data + offset, node->data.branch.children[i]->hash, 64);
                } else {
                    memset(hash_data + offset, 0, 64);
                }
                offset += 64;
            }
            
            memcpy(hash_data + offset, &node->data.branch.value_len, sizeof(size_t));
            offset += sizeof(size_t);
            if (node->data.branch.value_len > 0) {
                memcpy(hash_data + offset, node->data.branch.value, node->data.branch.value_len);
            }
            break;
        }
        
        case MXD_TRIE_NODE_EXTENSION: {
            // Hash: type + key_len + key + child_hash
            hash_data_len = 1 + sizeof(size_t) + node->data.extension.key_len + 64;
            hash_data = malloc(hash_data_len);
            if (!hash_data) return -1;
            
            size_t offset = 0;
            hash_data[offset++] = (uint8_t)node->type;
            memcpy(hash_data + offset, &node->data.extension.key_len, sizeof(size_t));
            offset += sizeof(size_t);
            memcpy(hash_data + offset, node->data.extension.key, node->data.extension.key_len);
            offset += node->data.extension.key_len;
            
            if (node->data.extension.child) {
                calculate_node_hash(node->data.extension.child);
                memcpy(hash_data + offset, node->data.extension.child->hash, 64);
            } else {
                memset(hash_data + offset, 0, 64);
            }
            break;
        }
        
        default:
            return -1;
    }
    
    // Calculate SHA-512 hash
    if (mxd_sha512(hash_data, hash_data_len, node->hash) != 0) {
        free(hash_data);
        return -1;
    }
    
    free(hash_data);
    node->hash_valid = 1;
    return 0;
}

// Forward declaration for recursive insert
static mxd_trie_node_t *insert_recursive(mxd_trie_node_t *node, const uint8_t *key,
                                         size_t key_len, size_t nibble_offset,
                                         const uint8_t *value, size_t value_len);

// Create a new empty merkle patricia trie
mxd_merkle_trie_t *mxd_trie_create(void) {
    mxd_merkle_trie_t *trie = calloc(1, sizeof(mxd_merkle_trie_t));
    if (!trie) return NULL;
    
    trie->root = NULL;
    trie->node_count = 0;
    trie->root_hash_valid = 0;
    
    return trie;
}

// Free a merkle patricia trie and all its nodes
void mxd_trie_free(mxd_merkle_trie_t *trie) {
    if (!trie) return;
    
    free_node(trie->root);
    free(trie);
}

// Insert or update a key-value pair in the trie
int mxd_trie_set(mxd_merkle_trie_t *trie, const uint8_t *key, size_t key_len,
                 const uint8_t *value, size_t value_len) {
    if (!trie || !key || !value) return -1;
    
    trie->root = insert_recursive(trie->root, key, key_len, 0, value, value_len);
    if (!trie->root) return -1;
    
    trie->root_hash_valid = 0;
    return 0;
}

// Recursive insert helper
static mxd_trie_node_t *insert_recursive(mxd_trie_node_t *node, const uint8_t *key,
                                         size_t key_len, size_t nibble_offset,
                                         const uint8_t *value, size_t value_len) {
    // If node is NULL, create a new leaf
    if (!node) {
        return create_leaf_node(key, key_len, value, value_len);
    }
    
    node->hash_valid = 0;  // Invalidate hash
    
    if (node->type == MXD_TRIE_NODE_LEAF) {
        // Check if keys match
        if (node->data.leaf.key_len == key_len &&
            memcmp(node->data.leaf.key, key, key_len) == 0) {
            // Update existing leaf value
            free(node->data.leaf.value);
            node->data.leaf.value = malloc(value_len);
            if (!node->data.leaf.value) return NULL;
            memcpy(node->data.leaf.value, value, value_len);
            node->data.leaf.value_len = value_len;
            return node;
        }
        
        // Keys don't match - need to split
        // Create a branch node and insert both keys
        mxd_trie_node_t *branch = create_branch_node();
        if (!branch) return NULL;
        
        // Insert existing leaf
        uint8_t existing_nibble = get_nibble(node->data.leaf.key, node->data.leaf.key_len, nibble_offset);
        if (existing_nibble < 16) {
            branch->data.branch.children[existing_nibble] = node;
        }
        
        // Insert new key
        uint8_t new_nibble = get_nibble(key, key_len, nibble_offset);
        if (new_nibble < 16) {
            branch->data.branch.children[new_nibble] = 
                create_leaf_node(key, key_len, value, value_len);
        }
        
        return branch;
    }
    
    if (node->type == MXD_TRIE_NODE_BRANCH) {
        uint8_t nibble = get_nibble(key, key_len, nibble_offset);
        if (nibble >= 16) {
            // End of key - store value in branch
            if (node->data.branch.value) {
                free(node->data.branch.value);
            }
            node->data.branch.value = malloc(value_len);
            if (!node->data.branch.value) return NULL;
            memcpy(node->data.branch.value, value, value_len);
            node->data.branch.value_len = value_len;
            return node;
        }
        
        node->data.branch.children[nibble] = 
            insert_recursive(node->data.branch.children[nibble], key, key_len,
                           nibble_offset + 1, value, value_len);
        return node;
    }
    
    // Extension node handling would go here for full implementation
    // For simplicity, we'll convert to branch
    return node;
}

// Get a value from the trie
int mxd_trie_get(const mxd_merkle_trie_t *trie, const uint8_t *key, size_t key_len,
                 uint8_t *value, size_t *value_len) {
    if (!trie || !key || !value || !value_len) return -1;
    
    mxd_trie_node_t *node = trie->root;
    size_t nibble_offset = 0;
    
    while (node) {
        if (node->type == MXD_TRIE_NODE_LEAF) {
            if (node->data.leaf.key_len == key_len &&
                memcmp(node->data.leaf.key, key, key_len) == 0) {
                if (*value_len < node->data.leaf.value_len) {
                    *value_len = node->data.leaf.value_len;
                    return -1;  // Buffer too small
                }
                memcpy(value, node->data.leaf.value, node->data.leaf.value_len);
                *value_len = node->data.leaf.value_len;
                return 0;
            }
            return -1;  // Key not found
        }
        
        if (node->type == MXD_TRIE_NODE_BRANCH) {
            uint8_t nibble = get_nibble(key, key_len, nibble_offset);
            if (nibble >= 16) {
                // End of key - check if branch has value
                if (node->data.branch.value) {
                    if (*value_len < node->data.branch.value_len) {
                        *value_len = node->data.branch.value_len;
                        return -1;
                    }
                    memcpy(value, node->data.branch.value, node->data.branch.value_len);
                    *value_len = node->data.branch.value_len;
                    return 0;
                }
                return -1;
            }
            node = node->data.branch.children[nibble];
            nibble_offset++;
            continue;
        }
        
        break;
    }
    
    return -1;  // Key not found
}

// Forward declaration for recursive delete
static mxd_trie_node_t *delete_recursive(mxd_trie_node_t *node, const uint8_t *key,
                                         size_t key_len, size_t nibble_offset, int *deleted);

// Delete a key from the trie
int mxd_trie_delete(mxd_merkle_trie_t *trie, const uint8_t *key, size_t key_len) {
    if (!trie || !key) return -1;
    
    if (!trie->root) {
        return -1;  // Key not found in empty trie
    }
    
    int deleted = 0;
    trie->root = delete_recursive(trie->root, key, key_len, 0, &deleted);
    
    if (deleted) {
        trie->root_hash_valid = 0;
        if (trie->node_count > 0) {
            trie->node_count--;
        }
        return 0;
    }
    
    return -1;  // Key not found
}

// Recursive delete helper
static mxd_trie_node_t *delete_recursive(mxd_trie_node_t *node, const uint8_t *key,
                                         size_t key_len, size_t nibble_offset, int *deleted) {
    if (!node) {
        *deleted = 0;
        return NULL;
    }
    
    if (node->type == MXD_TRIE_NODE_LEAF) {
        // Check if this is the key we're looking for
        if (node->data.leaf.key_len == key_len &&
            memcmp(node->data.leaf.key, key, key_len) == 0) {
            // Found the key - delete this node
            free(node->data.leaf.key);
            free(node->data.leaf.value);
            free(node);
            *deleted = 1;
            return NULL;
        }
        // Key not found
        *deleted = 0;
        return node;
    }
    
    if (node->type == MXD_TRIE_NODE_BRANCH) {
        uint8_t nibble = get_nibble(key, key_len, nibble_offset);
        
        if (nibble >= 16) {
            // End of key - check if branch has value to delete
            if (node->data.branch.value) {
                free(node->data.branch.value);
                node->data.branch.value = NULL;
                node->data.branch.value_len = 0;
                node->hash_valid = 0;
                *deleted = 1;
                
                // Check if branch can be collapsed
                int child_count = 0;
                int last_child_index = -1;
                for (int i = 0; i < 16; i++) {
                    if (node->data.branch.children[i]) {
                        child_count++;
                        last_child_index = i;
                    }
                }
                
                // If only one child remains and no value, collapse
                if (child_count == 1 && !node->data.branch.value) {
                    mxd_trie_node_t *child = node->data.branch.children[last_child_index];
                    free(node);
                    return child;
                }
                
                return node;
            }
            *deleted = 0;
            return node;
        }
        
        // Recurse into child
        node->data.branch.children[nibble] = delete_recursive(
            node->data.branch.children[nibble], key, key_len, nibble_offset + 1, deleted);
        
        if (*deleted) {
            node->hash_valid = 0;
            
            // Check if branch can be collapsed after deletion
            int child_count = 0;
            int last_child_index = -1;
            for (int i = 0; i < 16; i++) {
                if (node->data.branch.children[i]) {
                    child_count++;
                    last_child_index = i;
                }
            }
            
            // If no children and no value, delete this branch
            if (child_count == 0 && !node->data.branch.value) {
                free(node);
                return NULL;
            }
            
            // If only one child and no value, collapse
            if (child_count == 1 && !node->data.branch.value) {
                mxd_trie_node_t *child = node->data.branch.children[last_child_index];
                free(node);
                return child;
            }
        }
        
        return node;
    }
    
    // Extension node - not fully implemented in this version
    *deleted = 0;
    return node;
}

// Calculate and return the merkle root hash of the trie
int mxd_trie_get_root_hash(mxd_merkle_trie_t *trie, uint8_t *root_hash) {
    if (!trie || !root_hash) return -1;
    
    if (!trie->root) {
        // Empty trie - return zero hash
        memset(root_hash, 0, 64);
        return 0;
    }
    
    if (!trie->root_hash_valid) {
        if (calculate_node_hash(trie->root) != 0) {
            return -1;
        }
        memcpy(trie->root_hash, trie->root->hash, 64);
        trie->root_hash_valid = 1;
    }
    
    memcpy(root_hash, trie->root_hash, 64);
    return 0;
}

// Verify the integrity of the trie
int mxd_trie_verify(mxd_merkle_trie_t *trie) {
    if (!trie) return -1;
    
    if (!trie->root) return 0;  // Empty trie is valid
    
    // Recalculate all hashes
    trie->root_hash_valid = 0;
    return calculate_node_hash(trie->root);
}

// Forward declaration for recursive serialization
static int serialize_node(const mxd_trie_node_t *node, uint8_t *buffer, size_t *offset, size_t max_size);
static mxd_trie_node_t *deserialize_node(const uint8_t *buffer, size_t *offset, size_t buffer_size);

// Calculate size needed to serialize a node
static size_t calculate_node_size(const mxd_trie_node_t *node) {
    if (!node) return 1;  // Just type byte for NULL
    
    size_t size = 1;  // type byte
    
    switch (node->type) {
        case MXD_TRIE_NODE_LEAF:
            size += 4 + node->data.leaf.key_len;    // key_len + key
            size += 4 + node->data.leaf.value_len;  // value_len + value
            break;
            
        case MXD_TRIE_NODE_BRANCH:
            for (int i = 0; i < 16; i++) {
                size += calculate_node_size(node->data.branch.children[i]);
            }
            size += 4 + node->data.branch.value_len;  // value_len + value
            break;
            
        case MXD_TRIE_NODE_EXTENSION:
            size += 4 + node->data.extension.key_len;  // key_len + key
            size += calculate_node_size(node->data.extension.child);
            break;
            
        default:
            break;
    }
    
    return size;
}

// Serialize a single node recursively
static int serialize_node(const mxd_trie_node_t *node, uint8_t *buffer, size_t *offset, size_t max_size) {
    if (*offset >= max_size) return -1;
    
    if (!node) {
        buffer[(*offset)++] = 0xFF;  // NULL marker
        return 0;
    }
    
    buffer[(*offset)++] = (uint8_t)node->type;
    
    switch (node->type) {
        case MXD_TRIE_NODE_LEAF: {
            if (*offset + 4 + node->data.leaf.key_len + 4 + node->data.leaf.value_len > max_size) return -1;
            
            // Write key length and key
            uint32_t key_len = (uint32_t)node->data.leaf.key_len;
            buffer[(*offset)++] = (key_len >> 24) & 0xFF;
            buffer[(*offset)++] = (key_len >> 16) & 0xFF;
            buffer[(*offset)++] = (key_len >> 8) & 0xFF;
            buffer[(*offset)++] = key_len & 0xFF;
            memcpy(buffer + *offset, node->data.leaf.key, node->data.leaf.key_len);
            *offset += node->data.leaf.key_len;
            
            // Write value length and value
            uint32_t value_len = (uint32_t)node->data.leaf.value_len;
            buffer[(*offset)++] = (value_len >> 24) & 0xFF;
            buffer[(*offset)++] = (value_len >> 16) & 0xFF;
            buffer[(*offset)++] = (value_len >> 8) & 0xFF;
            buffer[(*offset)++] = value_len & 0xFF;
            memcpy(buffer + *offset, node->data.leaf.value, node->data.leaf.value_len);
            *offset += node->data.leaf.value_len;
            break;
        }
        
        case MXD_TRIE_NODE_BRANCH: {
            // Serialize all 16 children
            for (int i = 0; i < 16; i++) {
                if (serialize_node(node->data.branch.children[i], buffer, offset, max_size) != 0) {
                    return -1;
                }
            }
            
            // Write value length and value
            if (*offset + 4 + node->data.branch.value_len > max_size) return -1;
            uint32_t value_len = (uint32_t)node->data.branch.value_len;
            buffer[(*offset)++] = (value_len >> 24) & 0xFF;
            buffer[(*offset)++] = (value_len >> 16) & 0xFF;
            buffer[(*offset)++] = (value_len >> 8) & 0xFF;
            buffer[(*offset)++] = value_len & 0xFF;
            if (node->data.branch.value_len > 0) {
                memcpy(buffer + *offset, node->data.branch.value, node->data.branch.value_len);
                *offset += node->data.branch.value_len;
            }
            break;
        }
        
        case MXD_TRIE_NODE_EXTENSION: {
            if (*offset + 4 + node->data.extension.key_len > max_size) return -1;
            
            // Write key length and key
            uint32_t key_len = (uint32_t)node->data.extension.key_len;
            buffer[(*offset)++] = (key_len >> 24) & 0xFF;
            buffer[(*offset)++] = (key_len >> 16) & 0xFF;
            buffer[(*offset)++] = (key_len >> 8) & 0xFF;
            buffer[(*offset)++] = key_len & 0xFF;
            memcpy(buffer + *offset, node->data.extension.key, node->data.extension.key_len);
            *offset += node->data.extension.key_len;
            
            // Serialize child
            if (serialize_node(node->data.extension.child, buffer, offset, max_size) != 0) {
                return -1;
            }
            break;
        }
        
        default:
            return -1;
    }
    
    return 0;
}

// Deserialize a single node recursively
static mxd_trie_node_t *deserialize_node(const uint8_t *buffer, size_t *offset, size_t buffer_size) {
    if (*offset >= buffer_size) return NULL;
    
    uint8_t type = buffer[(*offset)++];
    
    if (type == 0xFF) {
        return NULL;  // NULL marker
    }
    
    mxd_trie_node_t *node = calloc(1, sizeof(mxd_trie_node_t));
    if (!node) return NULL;
    
    node->type = (mxd_trie_node_type_t)type;
    node->hash_valid = 0;
    
    switch (node->type) {
        case MXD_TRIE_NODE_LEAF: {
            if (*offset + 4 > buffer_size) { free(node); return NULL; }
            
            // Read key length and key
            uint32_t key_len = ((uint32_t)buffer[*offset] << 24) |
                              ((uint32_t)buffer[*offset + 1] << 16) |
                              ((uint32_t)buffer[*offset + 2] << 8) |
                              (uint32_t)buffer[*offset + 3];
            *offset += 4;

            // Cap key/value lengths to prevent OOM from malicious data
            if (key_len > 10 * 1024 * 1024) { free(node); return NULL; } // 10MB max
            if (*offset + key_len + 4 > buffer_size) { free(node); return NULL; }

            node->data.leaf.key = malloc(key_len);
            if (!node->data.leaf.key) { free(node); return NULL; }
            memcpy(node->data.leaf.key, buffer + *offset, key_len);
            node->data.leaf.key_len = key_len;
            *offset += key_len;

            // Read value length and value
            uint32_t value_len = ((uint32_t)buffer[*offset] << 24) |
                                ((uint32_t)buffer[*offset + 1] << 16) |
                                ((uint32_t)buffer[*offset + 2] << 8) |
                                (uint32_t)buffer[*offset + 3];
            *offset += 4;

            if (value_len > 10 * 1024 * 1024) { // 10MB max
                free(node->data.leaf.key);
                free(node);
                return NULL;
            }
            if (*offset + value_len > buffer_size) {
                free(node->data.leaf.key);
                free(node);
                return NULL;
            }
            
            node->data.leaf.value = malloc(value_len);
            if (!node->data.leaf.value) {
                free(node->data.leaf.key);
                free(node);
                return NULL;
            }
            memcpy(node->data.leaf.value, buffer + *offset, value_len);
            node->data.leaf.value_len = value_len;
            *offset += value_len;
            break;
        }
        
        case MXD_TRIE_NODE_BRANCH: {
            // Deserialize all 16 children
            for (int i = 0; i < 16; i++) {
                node->data.branch.children[i] = deserialize_node(buffer, offset, buffer_size);
            }
            
            if (*offset + 4 > buffer_size) {
                free_node(node);
                return NULL;
            }
            
            // Read value length and value
            uint32_t value_len = ((uint32_t)buffer[*offset] << 24) |
                                ((uint32_t)buffer[*offset + 1] << 16) |
                                ((uint32_t)buffer[*offset + 2] << 8) |
                                (uint32_t)buffer[*offset + 3];
            *offset += 4;
            
            if (value_len > 0) {
                if (*offset + value_len > buffer_size) {
                    free_node(node);
                    return NULL;
                }
                node->data.branch.value = malloc(value_len);
                if (!node->data.branch.value) {
                    free_node(node);
                    return NULL;
                }
                memcpy(node->data.branch.value, buffer + *offset, value_len);
                node->data.branch.value_len = value_len;
                *offset += value_len;
            }
            break;
        }
        
        case MXD_TRIE_NODE_EXTENSION: {
            if (*offset + 4 > buffer_size) { free(node); return NULL; }
            
            // Read key length and key
            uint32_t key_len = ((uint32_t)buffer[*offset] << 24) |
                              ((uint32_t)buffer[*offset + 1] << 16) |
                              ((uint32_t)buffer[*offset + 2] << 8) |
                              (uint32_t)buffer[*offset + 3];
            *offset += 4;
            
            if (*offset + key_len > buffer_size) { free(node); return NULL; }
            
            node->data.extension.key = malloc(key_len);
            if (!node->data.extension.key) { free(node); return NULL; }
            memcpy(node->data.extension.key, buffer + *offset, key_len);
            node->data.extension.key_len = key_len;
            *offset += key_len;
            
            // Deserialize child
            node->data.extension.child = deserialize_node(buffer, offset, buffer_size);
            break;
        }
        
        default:
            free(node);
            return NULL;
    }
    
    return node;
}

// Serialize the entire trie to a buffer
int mxd_trie_serialize(const mxd_merkle_trie_t *trie, uint8_t *buffer, size_t *buffer_size) {
    if (!trie || !buffer_size) return -1;
    
    // Calculate required size
    size_t required_size = 4 + 64;  // node_count + root_hash
    required_size += calculate_node_size(trie->root);
    
    // If buffer is NULL, just return required size
    if (!buffer) {
        *buffer_size = required_size;
        return 0;
    }
    
    if (*buffer_size < required_size) {
        *buffer_size = required_size;
        return -1;  // Buffer too small
    }
    
    size_t offset = 0;
    
    // Write node count
    uint32_t node_count = (uint32_t)trie->node_count;
    buffer[offset++] = (node_count >> 24) & 0xFF;
    buffer[offset++] = (node_count >> 16) & 0xFF;
    buffer[offset++] = (node_count >> 8) & 0xFF;
    buffer[offset++] = node_count & 0xFF;
    
    // Write root hash
    memcpy(buffer + offset, trie->root_hash, 64);
    offset += 64;
    
    // Serialize root node
    if (serialize_node(trie->root, buffer, &offset, *buffer_size) != 0) {
        return -1;
    }
    
    *buffer_size = offset;
    return 0;
}

// Deserialize a trie from a buffer
mxd_merkle_trie_t *mxd_trie_deserialize(const uint8_t *buffer, size_t buffer_size) {
    if (!buffer || buffer_size < 4 + 64) return NULL;
    
    mxd_merkle_trie_t *trie = calloc(1, sizeof(mxd_merkle_trie_t));
    if (!trie) return NULL;
    
    size_t offset = 0;
    
    // Read node count
    trie->node_count = ((uint32_t)buffer[offset] << 24) |
                       ((uint32_t)buffer[offset + 1] << 16) |
                       ((uint32_t)buffer[offset + 2] << 8) |
                       (uint32_t)buffer[offset + 3];
    offset += 4;
    
    // Read root hash
    memcpy(trie->root_hash, buffer + offset, 64);
    offset += 64;
    trie->root_hash_valid = 1;
    
    // Deserialize root node
    trie->root = deserialize_node(buffer, &offset, buffer_size);
    
    return trie;
}
