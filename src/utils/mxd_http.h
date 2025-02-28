#ifndef MXD_HTTP_H
#define MXD_HTTP_H

#include <stddef.h>

// HTTP response structure
typedef struct {
    char* data;
    size_t size;
    int status_code;
} mxd_http_response_t;

// HTTP client functions
mxd_http_response_t* mxd_http_get(const char* url);
void mxd_http_free_response(mxd_http_response_t* response);

#endif // MXD_HTTP_H
