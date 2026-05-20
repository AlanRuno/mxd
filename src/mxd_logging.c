#include "../include/mxd_logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>

static mxd_log_config_t current_config = {
    .level = MXD_LOG_INFO,
    .output_file = NULL,
    .enable_console = 1,
    .enable_json = 0
};

static FILE *log_file = NULL;
static int logging_initialized = 0;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

static const char* level_strings[] = {
    "ERROR", "WARN", "INFO", "DEBUG"
};

// Thread-local storage for timestamp buffer to ensure thread safety
static __thread char tls_timestamp[32];

static const char* get_timestamp(void) {
    time_t now = time(NULL);
    struct tm tm_info;
    gmtime_r(&now, &tm_info);  // Thread-safe version of gmtime
    strftime(tls_timestamp, sizeof(tls_timestamp), "%Y-%m-%dT%H:%M:%SZ", &tm_info);
    return tls_timestamp;
}

int mxd_init_logging(const mxd_log_config_t *config) {
    if (!config) {
        return -1;
    }
    
    current_config = *config;
    
    if (current_config.output_file) {
        log_file = fopen(current_config.output_file, "a");
        if (!log_file) {
            return -1;
        }
    }
    
    logging_initialized = 1;
    return 0;
}

void mxd_cleanup_logging(void) {
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
    logging_initialized = 0;
}

// Escape a string for safe JSON embedding. Writes to dst (up to dst_size bytes).
static void json_escape(const char *src, char *dst, size_t dst_size) {
    if (!src || !dst || dst_size == 0) return;
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j < dst_size - 1; i++) {
        char c = src[i];
        if (c == '"' || c == '\\') {
            if (j + 2 >= dst_size) break;
            dst[j++] = '\\';
            dst[j++] = c;
        } else if (c == '\n') {
            if (j + 2 >= dst_size) break;
            dst[j++] = '\\';
            dst[j++] = 'n';
        } else if (c == '\r') {
            if (j + 2 >= dst_size) break;
            dst[j++] = '\\';
            dst[j++] = 'r';
        } else if (c == '\t') {
            if (j + 2 >= dst_size) break;
            dst[j++] = '\\';
            dst[j++] = 't';
        } else if ((unsigned char)c < 0x20) {
            // Escape other control characters as \u00XX
            if (j + 6 >= dst_size) break;
            j += snprintf(dst + j, dst_size - j, "\\u%04x", (unsigned char)c);
        } else {
            dst[j++] = c;
        }
    }
    dst[j] = '\0';
}

void mxd_log(mxd_log_level_t level, const char *component, const char *format, ...) {
    if (!logging_initialized || level > current_config.level) {
        return;
    }

    va_list args;
    va_start(args, format);

    char message[1024];
    vsnprintf(message, sizeof(message), format, args);

    const char *timestamp = get_timestamp();

    // Lock mutex for thread-safe file and console output
    pthread_mutex_lock(&log_mutex);

    if (current_config.enable_json) {
        // Escape message and component to prevent JSON injection
        char escaped_message[2048];
        char escaped_component[256];
        json_escape(message, escaped_message, sizeof(escaped_message));
        json_escape(component ? component : "unknown", escaped_component, sizeof(escaped_component));

        char json_log[4096];
        snprintf(json_log, sizeof(json_log),
            "{\"timestamp\":\"%s\",\"level\":\"%s\",\"component\":\"%s\",\"message\":\"%s\"}\n",
            timestamp, level_strings[level], escaped_component, escaped_message);
        
        if (current_config.enable_console) {
            printf("%s", json_log);
            fflush(stdout);
        }
        if (log_file) {
            fprintf(log_file, "%s", json_log);
            fflush(log_file);
        }
    } else {
        char formatted_log[2048];
        snprintf(formatted_log, sizeof(formatted_log),
            "[%s] %s [%s]: %s\n",
            timestamp, level_strings[level], component ? component : "unknown", message);
        
        if (current_config.enable_console) {
            printf("%s", formatted_log);
            fflush(stdout);
        }
        if (log_file) {
            fprintf(log_file, "%s", formatted_log);
            fflush(log_file);
        }
    }
    
    pthread_mutex_unlock(&log_mutex);
    
    va_end(args);
}
