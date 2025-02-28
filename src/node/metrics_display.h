#ifndef MXD_METRICS_DISPLAY_H
#define MXD_METRICS_DISPLAY_H

#include "../include/mxd_metrics.h"
#include "../include/common/mxd_metrics_types.h"

/**
 * Clear the console screen and move cursor to top
 */
void clear_console(void);

/**
 * Display node metrics in a formatted console output
 * @param metrics Current node performance metrics
 * @param stake Current node stake information
 */
void display_node_metrics(const mxd_node_metrics_t* metrics, const mxd_node_stake_t* stake);

#endif // MXD_METRICS_DISPLAY_H
