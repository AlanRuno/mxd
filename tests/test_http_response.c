#define _GNU_SOURCE /* memmem */
/*
 * test_http_response.c — HTTP API responses larger than 16 KB, over a real socket.
 *
 * Background (devnet 2026-11): /utxos/<addr32> with 120 outputs returned 23,618
 * bytes of which only the first 16 KB of the response were right. The whole
 * response was formatted into a 16 KB stack buffer and sent with snprintf's return
 * value, so the rest was stack memory, including what remained of earlier requests.
 *
 * Checks are explicit rather than assert(): CI builds in Release, where NDEBUG
 * removes assert() and would leave this test passing whatever the server does.
 */

#include "../include/mxd_monitoring.h"
#include "../include/mxd_utxo.h"

#include <arpa/inet.h>
#include <cjson/cJSON.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TEST_PORT 28573
#define TEST_DB "./test_http_response.db"
#define BODY_MARKER "EARLIER_REQUEST_BODY_MARKER"

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        failures++; \
        printf("  FAIL %s:%d: ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } \
} while (0)

typedef struct {
    char *data;
    size_t len;
    const char *body;
    size_t body_len;
    size_t content_length;
    int status;
} http_reply_t;

static int connect_server(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        printf("connect failed\n");
        exit(1);
    }
    return fd;
}

static void send_request(int fd, const char *request, size_t len) {
    if (send(fd, request, len, 0) != (ssize_t)len) {
        printf("request send failed\n");
        exit(1);
    }
}

static http_reply_t exchange(const char *request, size_t request_len) {
    http_reply_t reply;
    memset(&reply, 0, sizeof(reply));
    int fd = connect_server();
    send_request(fd, request, request_len);

    size_t capacity = 1 << 16;
    reply.data = malloc(capacity + 1);
    for (;;) {
        if (reply.len == capacity) {
            capacity *= 2;
            reply.data = realloc(reply.data, capacity + 1);
        }
        ssize_t got = recv(fd, reply.data + reply.len, capacity - reply.len, 0);
        if (got <= 0) break;
        reply.len += (size_t)got;
    }
    close(fd);
    reply.data[reply.len] = '\0';

    const char *split = strstr(reply.data, "\r\n\r\n");
    if (split) {
        reply.body = split + 4;
        reply.body_len = reply.len - (size_t)(reply.body - reply.data);
    }
    sscanf(reply.data, "HTTP/1.1 %d", &reply.status);
    const char *header = strstr(reply.data, "Content-Length: ");
    if (header) reply.content_length = (size_t)strtoull(header + 16, NULL, 10);
    return reply;
}

static http_reply_t get(const char *path) {
    char request[256];
    int len = snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: test\r\n\r\n", path);
    return exchange(request, (size_t)len);
}

static void address_for(uint32_t count, uint8_t addr[32], char hex[65]) {
    memset(addr, 0, 32);
    addr[0] = 0xA5;
    memcpy(addr + 1, &count, sizeof(count));
    for (int i = 0; i < 32; i++) {
        snprintf(hex + i * 2, 3, "%02x", addr[i]);
    }
}

static void tx_hash_for(uint32_t count, uint32_t index, uint8_t hash[64]) {
    memset(hash, 0x11, 64);
    memcpy(hash, &count, sizeof(count));
    memcpy(hash + 4, &index, sizeof(index));
}

static void add_outputs(uint32_t count) {
    uint8_t addr[32];
    char hex[65];
    address_for(count, addr, hex);
    for (uint32_t i = 0; i < count; i++) {
        mxd_utxo_t utxo;
        memset(&utxo, 0, sizeof(utxo));
        tx_hash_for(count, i, utxo.tx_hash);
        utxo.output_index = i;
        memcpy(utxo.owner_key, addr, sizeof(utxo.owner_key));
        utxo.amount = 1000000 + (mxd_amount_t)i;
        if (mxd_add_utxo(&utxo) != 0) {
            printf("mxd_add_utxo failed\n");
            exit(1);
        }
    }
}

/* Every output comes back exactly once, in a body that is whole and valid JSON. */
static void check_full_list(uint32_t count) {
    uint8_t addr[32];
    char hex[65];
    char path[128];
    address_for(count, addr, hex);
    snprintf(path, sizeof(path), "/utxos/%s", hex);

    http_reply_t reply = get(path);
    printf("  %u outputs: %zu bytes\n", count, reply.len);
    CHECK(reply.status == 200, "%u outputs: status %d", count, reply.status);
    CHECK(reply.body != NULL, "%u outputs: no header terminator", count);
    CHECK(reply.body_len == reply.content_length, "%u outputs: body %zu, Content-Length %zu",
          count, reply.body_len, reply.content_length);
    CHECK(strlen(reply.data) == reply.len, "%u outputs: NUL byte at offset %zu of %zu",
          count, strlen(reply.data), reply.len);

    cJSON *root = reply.body ? cJSON_ParseWithLength(reply.body, reply.body_len) : NULL;
    CHECK(root != NULL, "%u outputs: body is not valid JSON", count);
    if (root) {
        const cJSON *address = cJSON_GetObjectItem(root, "address");
        const cJSON *list = cJSON_GetObjectItem(root, "utxos");
        CHECK(cJSON_IsString(address) && strcmp(address->valuestring, hex) == 0,
              "%u outputs: wrong address", count);
        CHECK(cJSON_GetArraySize(list) == (int)count, "%u outputs: %d listed",
              count, cJSON_GetArraySize(list));

        uint8_t *seen = calloc(count, 1);
        const cJSON *item = NULL;
        cJSON_ArrayForEach(item, list) {
            const cJSON *index = cJSON_GetObjectItem(item, "output_index");
            const cJSON *hash = cJSON_GetObjectItem(item, "tx_hash");
            const cJSON *amount = cJSON_GetObjectItem(item, "amount");
            uint32_t i = cJSON_IsNumber(index) ? (uint32_t)index->valuedouble : count;
            if (i >= count || !cJSON_IsString(hash) || !cJSON_IsNumber(amount)) {
                CHECK(0, "%u outputs: malformed entry", count);
                continue;
            }
            uint8_t expected[64];
            char expected_hex[129];
            tx_hash_for(count, i, expected);
            for (int b = 0; b < 64; b++) {
                snprintf(expected_hex + b * 2, 3, "%02x", expected[b]);
            }
            CHECK(!seen[i], "%u outputs: index %u listed twice", count, i);
            CHECK(strcmp(hash->valuestring, expected_hex) == 0, "%u outputs: wrong hash at %u", count, i);
            CHECK((uint64_t)amount->valuedouble == 1000000ULL + i, "%u outputs: wrong amount at %u", count, i);
            seen[i] = 1;
        }
        free(seen);
        cJSON_Delete(root);
    }
    free(reply.data);
}

/* A wallet may depend on these exact bytes: small lists must not change. */
static void check_small_format(void) {
    uint8_t addr[32];
    char hex[65];
    char path[128];
    char expected[1024];
    uint8_t hash[64];
    char hash_hex[129];

    address_for(1, addr, hex);
    tx_hash_for(1, 0, hash);
    for (int b = 0; b < 64; b++) {
        snprintf(hash_hex + b * 2, 3, "%02x", hash[b]);
    }
    snprintf(path, sizeof(path), "/utxos/%s", hex);
    snprintf(expected, sizeof(expected),
             "{\"address\":\"%s\",\"utxos\":[{\"tx_hash\":\"%s\",\"output_index\":0,"
             "\"amount\":1000000,\"amount_mxd\":0.01}]}", hex, hash_hex);

    http_reply_t reply = get(path);
    CHECK(reply.status == 200, "small list: status %d", reply.status);
    CHECK(reply.body && strcmp(reply.body, expected) == 0, "small list changed: %s", reply.body ? reply.body : "");
    CHECK(reply.body_len == reply.content_length, "small list: body %zu, Content-Length %zu",
          reply.body_len, reply.content_length);
    CHECK(strstr(reply.data, "Content-Type: application/json\r\n") != NULL, "small list: Content-Type");
    CHECK(strstr(reply.data, "Connection: close\r\n") != NULL, "small list: Connection");
    CHECK(strstr(reply.data, "Access-Control-Allow-Origin: *\r\n") != NULL, "small list: CORS");
    free(reply.data);

    address_for(7777, addr, hex);
    snprintf(path, sizeof(path), "/utxos/%s", hex);
    snprintf(expected, sizeof(expected), "{\"address\":\"%s\",\"utxos\":[]}", hex);
    reply = get(path);
    CHECK(reply.body && strcmp(reply.body, expected) == 0, "empty list changed: %s", reply.body ? reply.body : "");
    free(reply.data);
}

/* What an earlier client sent must never reach a later one. */
static void check_no_leftovers(uint32_t count) {
    char body[4096];
    char request[5120];
    memset(body, 'x', sizeof(body));
    /* Deep enough that the next request does not simply overwrite it. */
    memcpy(body + 2048, BODY_MARKER, strlen(BODY_MARKER));
    int len = snprintf(request, sizeof(request),
                       "POST /no-such-path HTTP/1.1\r\nHost: test\r\nContent-Length: %zu\r\n\r\n%.*s",
                       sizeof(body), (int)sizeof(body), body);
    http_reply_t earlier = exchange(request, (size_t)len);
    free(earlier.data);

    uint8_t addr[32];
    char hex[65];
    char path[128];
    address_for(count, addr, hex);
    snprintf(path, sizeof(path), "/utxos/%s", hex);
    http_reply_t reply = get(path);
    CHECK(memmem(reply.data, reply.len, BODY_MARKER, strlen(BODY_MARKER)) == NULL,
          "response carries data from an earlier request");
    free(reply.data);
}

/* Under AddressSanitizer freed blocks stay in quarantine and still count in
 * VmRSS, so measure the bytes the allocator holds live instead. */
#if defined(__SANITIZE_ADDRESS__)
#define HTTP_TEST_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define HTTP_TEST_ASAN 1
#endif
#endif

#ifdef HTTP_TEST_ASAN
#include <sanitizer/allocator_interface.h>
#endif

static long resident_kb(void) {
#ifdef HTTP_TEST_ASAN
    return (long)(__sanitizer_get_current_allocated_bytes() / 1024);
#else
    long kb = -1;
    char line[128];
    FILE *status = fopen("/proc/self/status", "r");
    if (!status) return -1;
    while (fgets(line, sizeof(line), status)) {
        if (sscanf(line, "VmRSS: %ld", &kb) == 1) break;
    }
    fclose(status);
    return kb;
#endif
}

/* Each lookup must give its memory back. 50 lookups of about 1 MB each would add
 * about 50 MB if the body were kept. */
static void check_memory_is_released(uint32_t count) {
    uint8_t addr[32];
    char hex[65];
    char path[128];
    address_for(count, addr, hex);
    snprintf(path, sizeof(path), "/utxos/%s", hex);

    for (int i = 0; i < 5; i++) {
        free(get(path).data);
    }
    long before = resident_kb();
    for (int i = 0; i < 50; i++) {
        free(get(path).data);
    }
    long after = resident_kb();
#ifdef HTTP_TEST_ASAN
    printf("  allocated memory %ld kB -> %ld kB\n", before, after);
#else
    printf("  resident memory %ld kB -> %ld kB\n", before, after);
#endif
    if (before >= 0 && after >= 0) {
        CHECK(after - before < 25 * 1024, "grew by %ld kB over 50 lookups", after - before);
    }

    http_reply_t reply = get("/utxos/not-an-address");
    CHECK(reply.status == 200 && reply.body && strcmp(reply.body, "{\"error\":\"Invalid address\"}") == 0,
          "invalid address changed: %s", reply.body ? reply.body : "");
    free(reply.data);
}

/* A client that asks for a large list and stops reading delays others only for a
 * bounded time, and does not stop the server. */
static void check_stalled_client(uint32_t count) {
    uint8_t addr[32];
    char hex[65];
    char request[256];
    address_for(count, addr, hex);
    int len = snprintf(request, sizeof(request), "GET /utxos/%s HTTP/1.1\r\nHost: test\r\n\r\n", hex);

    int small = 4096;
    int stalled = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(stalled, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));
    struct sockaddr_in server;
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(TEST_PORT);
    inet_pton(AF_INET, "127.0.0.1", &server.sin_addr);
    if (connect(stalled, (struct sockaddr *)&server, sizeof(server)) != 0) {
        printf("connect failed\n");
        exit(1);
    }
    send_request(stalled, request, (size_t)len);
    usleep(200000);

    time_t started = time(NULL);
    http_reply_t reply = get("/chain_id");
    time_t waited = time(NULL) - started;
    printf("  next request answered after %ld s\n", (long)waited);
    CHECK(reply.status == 200, "server did not answer after a stalled client: %d", reply.status);
    CHECK(waited <= 45, "stalled client held the server for %ld s", (long)waited);
    free(reply.data);
    close(stalled);
}

int main(void) {
    /* Sizes around the old limit, the reported case, and more than socket buffers
     * accept in one call. */
    static const uint32_t sizes[] = { 1, 80, 81, 82, 83, 120, 5000 };
    const uint32_t stall_size = 60000;

    if (system("rm -rf " TEST_DB) != 0 || mxd_init_utxo_db(TEST_DB) != 0) {
        printf("database setup failed\n");
        return 1;
    }
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        add_outputs(sizes[i]);
    }
    add_outputs(stall_size);

    if (mxd_init_monitoring(TEST_PORT) != 0 || mxd_start_metrics_server() != 0) {
        printf("server setup failed\n");
        return 1;
    }

    printf("Small lists keep their format\n");
    check_small_format();

    printf("Lists around and above 16 KB are complete\n");
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        check_full_list(sizes[i]);
    }

    printf("Earlier requests do not leak\n");
    check_no_leftovers(120);

    printf("Lookups release their memory\n");
    check_memory_is_released(5000);

    printf("A stalled client does not stop the server\n");
    check_stalled_client(stall_size);
    check_full_list(stall_size);

    /* The accept thread stays blocked in accept(); leave without joining it. */
    mxd_close_utxo_db();
    if (system("rm -rf " TEST_DB) != 0) {
        printf("database cleanup failed\n");
    }

    printf(failures ? "FAILED: %d check(s)\n" : "All HTTP response checks passed\n", failures);
    fflush(stdout);
    _exit(failures ? 1 : 0);
}
