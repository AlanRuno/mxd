#ifndef MXD_ERROR_H
#define MXD_ERROR_H

#include <string.h>

#define MXD_OK              0
#define MXD_ERR_GENERIC    -1   // Not found, already spent, parse error (skip-safe)
#define MXD_ERR_IO         -2   // RocksDB IO/write failure (must halt)
#define MXD_ERR_DISK_FULL  -3   // Disk space below threshold (must halt)
#define MXD_ERR_BRIDGE_INVALID -4  // Invalid bridge transaction in block (reject block)

static inline int mxd_is_io_error(const char *err) {
    return err && (strstr(err, "IO error") || strstr(err, "No space"));
}

#endif // MXD_ERROR_H
