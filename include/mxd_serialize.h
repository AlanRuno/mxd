#ifndef MXD_SERIALIZE_H
#define MXD_SERIALIZE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>
#include "mxd_endian.h"

// Canonical serialization helpers for cross-platform compatibility
// All multi-byte integers are stored in big-endian (network byte order)

// Write helpers (append to buffer, advance pointer)

static inline void mxd_write_u8(uint8_t **buf, uint8_t val) {
    **buf = val;
    (*buf)++;
}

static inline void mxd_write_u16_be(uint8_t **buf, uint16_t val) {
    uint16_t be = htons(val);
    memcpy(*buf, &be, 2);
    *buf += 2;
}

static inline void mxd_write_u32_be(uint8_t **buf, uint32_t val) {
    uint32_t be = htonl(val);
    memcpy(*buf, &be, 4);
    *buf += 4;
}

static inline void mxd_write_u64_be(uint8_t **buf, uint64_t val) {
    uint64_t be = mxd_htonll(val);
    memcpy(*buf, &be, 8);
    *buf += 8;
}

static inline void mxd_write_bytes(uint8_t **buf, const uint8_t *data, size_t len) {
    if (data && len > 0) {
        memcpy(*buf, data, len);
        *buf += len;
    }
}

// Read helpers (read from buffer, advance pointer)

static inline uint8_t mxd_read_u8(const uint8_t **buf) {
    uint8_t val = **buf;
    (*buf)++;
    return val;
}

static inline uint16_t mxd_read_u16_be(const uint8_t **buf) {
    uint16_t be;
    memcpy(&be, *buf, 2);
    *buf += 2;
    return ntohs(be);
}

static inline uint32_t mxd_read_u32_be(const uint8_t **buf) {
    uint32_t be;
    memcpy(&be, *buf, 4);
    *buf += 4;
    return ntohl(be);
}

static inline uint64_t mxd_read_u64_be(const uint8_t **buf) {
    uint64_t be;
    memcpy(&be, *buf, 8);
    *buf += 8;
    return mxd_ntohll(be);
}

static inline void mxd_read_bytes(const uint8_t **buf, uint8_t *data, size_t len) {
    if (data && len > 0) {
        memcpy(data, *buf, len);
        *buf += len;
    }
}

// Peek helpers (read without advancing pointer)

static inline uint8_t mxd_peek_u8(const uint8_t *buf) {
    return *buf;
}

static inline uint16_t mxd_peek_u16_be(const uint8_t *buf) {
    uint16_t be;
    memcpy(&be, buf, 2);
    return ntohs(be);
}

static inline uint32_t mxd_peek_u32_be(const uint8_t *buf) {
    uint32_t be;
    memcpy(&be, buf, 4);
    return ntohl(be);
}

static inline uint64_t mxd_peek_u64_be(const uint8_t *buf) {
    uint64_t be;
    memcpy(&be, buf, 8);
    return mxd_ntohll(be);
}

// Helper to create big-endian database keys
static inline void mxd_create_key_with_u32(uint8_t *key, size_t *key_len, 
                                           const char *prefix, uint32_t value) {
    size_t prefix_len = strlen(prefix);
    memcpy(key, prefix, prefix_len);
    uint32_t be_value = htonl(value);
    memcpy(key + prefix_len, &be_value, 4);
    *key_len = prefix_len + 4;
}

static inline void mxd_create_key_with_u64(uint8_t *key, size_t *key_len,
                                           const char *prefix, uint64_t value) {
    size_t prefix_len = strlen(prefix);
    memcpy(key, prefix, prefix_len);
    uint64_t be_value = mxd_htonll(value);
    memcpy(key + prefix_len, &be_value, 8);
    *key_len = prefix_len + 8;
}

#ifdef __cplusplus
}
#endif

#endif // MXD_SERIALIZE_H
