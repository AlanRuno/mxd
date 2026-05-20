#include "../include/mxd_utxo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int mxd_get_utxo(const uint8_t tx_hash[64], uint32_t output_index, mxd_utxo_t *utxo) {
    if (!tx_hash || !utxo) {
        return -1;
    }
    
    return mxd_find_utxo(tx_hash, output_index, utxo);
}
