#ifndef MXD_ROCKSDB_GLOBALS_H
#define MXD_ROCKSDB_GLOBALS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <rocksdb/c.h>

// Accessor functions for global RocksDB variables
rocksdb_t *mxd_get_rocksdb_db(void);
rocksdb_readoptions_t *mxd_get_rocksdb_readoptions(void);
rocksdb_writeoptions_t *mxd_get_rocksdb_writeoptions(void);

void mxd_set_rocksdb_db(rocksdb_t *db);
void mxd_set_rocksdb_readoptions(rocksdb_readoptions_t *options);
void mxd_set_rocksdb_writeoptions(rocksdb_writeoptions_t *options);

#ifdef __cplusplus
}
#endif

#endif // MXD_ROCKSDB_GLOBALS_H
