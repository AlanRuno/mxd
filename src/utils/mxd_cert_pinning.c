#include "mxd_cert_pinning.h"
#include "../../include/mxd_logging.h"
#include "../metrics/mxd_prometheus.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

int mxd_init_cert_pins(mxd_cert_pins_t* pins, char pinned_keys[][256], int count) {
    if (!pins || count <= 0) {
        return -1;
    }
    
    pins->pinned_keys = malloc(count * sizeof(char*));
    if (!pins->pinned_keys) {
        return -1;
    }
    
    pins->count = count;
    for (int i = 0; i < count; i++) {
        pins->pinned_keys[i] = strdup(pinned_keys[i]);
        if (!pins->pinned_keys[i]) {
            for (int j = 0; j < i; j++) {
                free(pins->pinned_keys[j]);
            }
            free(pins->pinned_keys);
            return -1;
        }
    }
    
    return 0;
}

void mxd_free_cert_pins(mxd_cert_pins_t* pins) {
    if (!pins) {
        return;
    }
    
    if (pins->pinned_keys) {
        for (int i = 0; i < pins->count; i++) {
            free(pins->pinned_keys[i]);
        }
        free(pins->pinned_keys);
    }
    
    pins->pinned_keys = NULL;
    pins->count = 0;
}

static char* get_cert_spki_hash(X509* cert) {
    if (!cert) {
        return NULL;
    }
    
    EVP_PKEY* pubkey = X509_get_pubkey(cert);
    if (!pubkey) {
        return NULL;
    }
    
    unsigned char* spki = NULL;
    int spki_len = i2d_PUBKEY(pubkey, &spki);
    EVP_PKEY_free(pubkey);
    
    if (spki_len <= 0 || !spki) {
        return NULL;
    }
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        OPENSSL_free(spki);
        return NULL;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, spki, spki_len) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        OPENSSL_free(spki);
        return NULL;
    }
    
    EVP_MD_CTX_free(ctx);
    OPENSSL_free(spki);
    
    char* hash_str = malloc(hash_len * 2 + 1);
    if (!hash_str) {
        return NULL;
    }
    
    for (unsigned int i = 0; i < hash_len; i++) {
        snprintf(hash_str + (i * 2), 3, "%02x", hash[i]);
    }
    hash_str[hash_len * 2] = '\0';
    
    return hash_str;
}

CURLcode mxd_verify_certificate_pin(CURL* curl, const char* url, mxd_cert_pins_t* pins) {
    if (!curl || !url || !pins || pins->count == 0) {
        return CURLE_OK;
    }
    
    if (strstr(url, "mxd.network") == NULL) {
        return CURLE_OK;
    }
    
    struct curl_certinfo* certinfo = NULL;
    CURLcode res = curl_easy_getinfo(curl, CURLINFO_CERTINFO, &certinfo);
    
    if (res != CURLE_OK || !certinfo) {
        MXD_LOG_WARN("cert_pinning", "Failed to get certificate info for %s", url);
        return CURLE_OK;
    }
    
    if (certinfo->num_of_certs == 0) {
        MXD_LOG_ERROR("cert_pinning", "No certificates found for %s", url);
        mxd_metrics_increment("mxd_cert_pinning_failures_total");
        return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
    }
    
    for (int i = 0; i < certinfo->num_of_certs; i++) {
        struct curl_slist* slist = certinfo->certinfo[i];
        
        for (struct curl_slist* node = slist; node; node = node->next) {
            if (strncmp(node->data, "Cert:", 5) == 0) {
                const char* cert_pem = node->data + 5;
                
                BIO* bio = BIO_new_mem_buf(cert_pem, -1);
                if (!bio) {
                    continue;
                }
                
                X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
                BIO_free(bio);
                
                if (!cert) {
                    continue;
                }
                
                char* hash = get_cert_spki_hash(cert);
                X509_free(cert);
                
                if (!hash) {
                    continue;
                }
                
                int match = 0;
                for (int j = 0; j < pins->count; j++) {
                    if (strcmp(hash, pins->pinned_keys[j]) == 0) {
                        match = 1;
                        break;
                    }
                }
                
                free(hash);
                
                if (match) {
                    MXD_LOG_INFO("cert_pinning", "Certificate pin matched for %s", url);
                    return CURLE_OK;
                }
            }
        }
    }
    
    MXD_LOG_ERROR("cert_pinning", "Certificate pin mismatch for %s", url);
    mxd_metrics_increment("mxd_cert_pinning_failures_total");
    return CURLE_SSL_PINNEDPUBKEYNOTMATCH;
}
