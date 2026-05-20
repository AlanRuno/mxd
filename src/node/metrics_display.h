#ifndef MXD_METRICS_DISPLAY_H
#define MXD_METRICS_DISPLAY_H

#include "../include/mxd_metrics.h"
#include "../include/common/mxd_metrics_types.h"
#include "../include/mxd_config.h"
#include "../include/mxd_rsc.h"

/**
 * Clear the console screen and move cursor to top
 */
void clear_console(void);

/**
 * Display node metrics in a formatted console output
 * @param metrics Current node performance metrics
 * @param stake Current node stake information
 * @param config Node configuration
 * @param rapid_table Rapid stake table with validator information
 * @param blockchain_height Current blockchain height
 * @param latest_block_hash Hash of the latest block (or NULL if no blocks)
 */
void display_node_metrics(const mxd_node_metrics_t* metrics, const mxd_node_stake_t* stake,
                         const mxd_config_t* config, const mxd_rapid_table_t* rapid_table,
                         uint32_t blockchain_height, const uint8_t* latest_block_hash);

#endif // MXD_METRICS_DISPLAY_H
