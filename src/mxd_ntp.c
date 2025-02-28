#include "../include/mxd_ntp.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

// NTP packet structure (RFC 5905)
typedef struct {
    uint8_t li_vn_mode;      // Leap indicator, version and mode
    uint8_t stratum;         // Stratum level
    uint8_t poll;            // Poll interval
    uint8_t precision;       // Precision
    uint32_t root_delay;     // Root delay
    uint32_t root_dispersion;// Root dispersion
    uint32_t ref_id;         // Reference ID
    uint64_t ref_ts;         // Reference timestamp
    uint64_t orig_ts;        // Originate timestamp
    uint64_t recv_ts;        // Receive timestamp
    uint64_t trans_ts;       // Transmit timestamp
} mxd_ntp_packet_t;

// Default NTP server pool
static const char *ntp_servers[] = {
    "pool.ntp.org",
    "time.google.com",
    "time.cloudflare.com"
};

static uint64_t last_sync_time = 0;
static uint64_t network_time_offset = 0;

// Initialize NTP synchronization
int mxd_init_ntp(void) {
    mxd_ntp_info_t info;
    return mxd_sync_time(&info);
}

// Get current time in milliseconds
static uint64_t get_current_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

// Synchronize with NTP servers
int mxd_sync_time(mxd_ntp_info_t *info) {
    if (!info) {
        return -1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        return -1;
    }

    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    // Try each NTP server
    for (size_t i = 0; i < sizeof(ntp_servers) / sizeof(ntp_servers[0]); i++) {
        struct hostent *server = gethostbyname(ntp_servers[i]);
        if (!server) {
            continue;
        }

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(123); // NTP port
        memcpy(&server_addr.sin_addr, server->h_addr, server->h_length);

        // Prepare NTP packet
        mxd_ntp_packet_t packet;
        memset(&packet, 0, sizeof(packet));
        packet.li_vn_mode = 0x1B; // Version 3, Mode 3 (client)

        // Record send time
        uint64_t send_time = get_current_time_ms();

        // Send request
        if (sendto(sock, &packet, sizeof(packet), 0,
                   (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            continue;
        }

        // Receive response
        if (recvfrom(sock, &packet, sizeof(packet), 0, NULL, NULL) < 0) {
            continue;
        }

        // Calculate network delay and offset
        uint64_t recv_time = get_current_time_ms();
        uint32_t delay = (uint32_t)(recv_time - send_time);
        
        // Convert NTP timestamp to milliseconds (NTP epoch starts at 1900)
        uint64_t ntp_time = ntohl(packet.trans_ts >> 32);
        ntp_time = (ntp_time - 2208988800ULL) * 1000; // Convert to Unix epoch
        
        // Update network time offset
        network_time_offset = ntp_time - recv_time;
        last_sync_time = recv_time;

        // Fill info structure
        info->timestamp = ntp_time;
        info->precision = 1000; // 1ms precision
        info->delay = delay;

        close(sock);
        return 0;
    }

    close(sock);
    return -1;
}

// Get current network time
int mxd_get_network_time(uint64_t *timestamp) {
    if (!timestamp) {
        return -1;
    }

    // Check if we need to resync (every hour)
    uint64_t current_time = get_current_time_ms();
    if (current_time - last_sync_time > 3600000) {
        mxd_ntp_info_t info;
        if (mxd_sync_time(&info) != 0) {
            return -1;
        }
    }

    *timestamp = get_current_time_ms() + network_time_offset;
    return 0;
}
