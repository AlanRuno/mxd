#include <rocksdb/c.h>

rocksdb_t *g_rocksdb_db = NULL;
rocksdb_readoptions_t *g_rocksdb_readoptions = NULL;
rocksdb_writeoptions_t *g_rocksdb_writeoptions = NULL;

rocksdb_t *mxd_get_rocksdb_db(void) {
    return g_rocksdb_db;
}

rocksdb_readoptions_t *mxd_get_rocksdb_readoptions(void) {
    return g_rocksdb_readoptions;
}

rocksdb_writeoptions_t *mxd_get_rocksdb_writeoptions(void) {
    return g_rocksdb_writeoptions;
}

void mxd_set_rocksdb_db(rocksdb_t *db) {
    g_rocksdb_db = db;
}

void mxd_set_rocksdb_readoptions(rocksdb_readoptions_t *options) {
    g_rocksdb_readoptions = options;
}

void mxd_set_rocksdb_writeoptions(rocksdb_writeoptions_t *options) {
    g_rocksdb_writeoptions = options;
}
