#ifndef MXD_CERT_PINNING_H
#define MXD_CERT_PINNING_H

#include <curl/curl.h>

typedef struct {
    char** pinned_keys;
    int count;
} mxd_cert_pins_t;

CURLcode mxd_verify_certificate_pin(CURL* curl, const char* url, mxd_cert_pins_t* pins);

int mxd_init_cert_pins(mxd_cert_pins_t* pins, char pinned_keys[][256], int count);

void mxd_free_cert_pins(mxd_cert_pins_t* pins);

#endif
