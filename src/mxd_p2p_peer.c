#include "../include/mxd_p2p.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int mxd_get_peer(const char *address, uint16_t port, mxd_peer_t *peer) {
    if (!address || !peer) {
        return -1;
    }
    
    mxd_peer_t peers[MXD_MAX_PEERS];
    size_t peer_count = MXD_MAX_PEERS;
    if (mxd_get_peers(peers, &peer_count) != 0) {
        return -1;
    }
    
    for (size_t i = 0; i < peer_count; i++) {
        if (strcmp(peers[i].address, address) == 0 && peers[i].port == port) {
            memcpy(peer, &peers[i], sizeof(mxd_peer_t));
            return 0;
        }
    }
    
    return -1; // Peer not found
}
