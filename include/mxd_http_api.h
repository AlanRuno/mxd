#ifndef MXD_HTTP_API_H
#define MXD_HTTP_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

// Initialize and start the HTTP API server
// Returns 0 on success, -1 on failure
int mxd_http_api_start(uint16_t port);

// Stop the HTTP API server
void mxd_http_api_stop(void);

// Check if the HTTP API server is running
int mxd_http_api_is_running(void);

#ifdef __cplusplus
}
#endif

#endif // MXD_HTTP_API_H
