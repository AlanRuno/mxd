#ifndef MEMORY_UTILS_H
#define MEMORY_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/mxd_logging.h"

static inline void log_memory_usage(const char* phase) {
    FILE* status = fopen("/proc/self/status", "r");
    if (!status) {
        return;
    }
    
    char line[256];
    long vm_size = 0;
    long vm_rss = 0;
    
    while (fgets(line, sizeof(line), status)) {
        if (strncmp(line, "VmSize:", 7) == 0) {
            sscanf(line + 7, "%ld", &vm_size);
        } else if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%ld", &vm_rss);
        }
    }
    
    fclose(status);
    
    MXD_LOG_DEBUG("memory_utils", "%s: VmSize=%ld KB (%.1f MB), VmRSS=%ld KB (%.1f MB)", 
                  phase, vm_size, vm_size / 1024.0, vm_rss, vm_rss / 1024.0);
}

#endif // MEMORY_UTILS_H
