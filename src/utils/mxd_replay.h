#ifndef MXD_REPLAY_H
#define MXD_REPLAY_H

#include <stdint.h>
#include <stddef.h>

#define MXD_REPLAY_CACHE_SIZE 1000
#define MXD_REPLAY_TTL_SECONDS 300

typedef struct {
    uint8_t challenge[32];
    uint64_t timestamp;
    uint64_t seen_at;
    int active;
} mxd_replay_entry_t;

int mxd_replay_init(void);

void mxd_replay_cleanup(void);

int mxd_replay_check(const uint8_t challenge[32], uint64_t timestamp);

int mxd_replay_record(const uint8_t challenge[32], uint64_t timestamp);

// Atomic check + record: prevents TOCTOU race between separate check and record calls
int mxd_replay_check_and_record(const uint8_t challenge[32], uint64_t timestamp);

void mxd_replay_cleanup_expired(void);

#endif
