#ifndef MXD_LOGGING_H
#define MXD_LOGGING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

typedef enum {
    MXD_LOG_ERROR = 0,
    MXD_LOG_WARN = 1,
    MXD_LOG_INFO = 2,
    MXD_LOG_DEBUG = 3
} mxd_log_level_t;

typedef struct {
    mxd_log_level_t level;
    const char *output_file;
    int enable_console;
    int enable_json;
} mxd_log_config_t;

int mxd_init_logging(const mxd_log_config_t *config);
void mxd_cleanup_logging(void);
void mxd_log(mxd_log_level_t level, const char *component, const char *format, ...);

#define MXD_LOG_ERROR(component, ...) mxd_log(MXD_LOG_ERROR, component, __VA_ARGS__)
#define MXD_LOG_WARN(component, ...) mxd_log(MXD_LOG_WARN, component, __VA_ARGS__)
#define MXD_LOG_INFO(component, ...) mxd_log(MXD_LOG_INFO, component, __VA_ARGS__)
#define MXD_LOG_DEBUG(component, ...) mxd_log(MXD_LOG_DEBUG, component, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // MXD_LOGGING_H
