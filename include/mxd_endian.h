#ifndef MXD_ENDIAN_H
#define MXD_ENDIAN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <arpa/inet.h>

// 64-bit byte order conversion helpers
static inline uint64_t mxd_htonll(uint64_t host_value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl((uint32_t)(host_value & 0xFFFFFFFF)) << 32) |
           htonl((uint32_t)(host_value >> 32));
#else
    return host_value;
#endif
}

static inline uint64_t mxd_ntohll(uint64_t net_value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)ntohl((uint32_t)(net_value & 0xFFFFFFFF)) << 32) |
           ntohl((uint32_t)(net_value >> 32));
#else
    return net_value;
#endif
}

#ifdef __cplusplus
}
#endif

#endif // MXD_ENDIAN_H
