#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <cjson/cJSON.h>
#include "mxd_config.h"
#include "utils/mxd_http.h"

static char* trim(char* str) {
    char* end;
    while(isspace((unsigned char)*str)) str++;
    if(*str == 0) return str;
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    return str;
}

static char* strip_quotes(char* str) {
    size_t len = strlen(str);
    if (len >= 2 && str[0] == '"' && str[len-1] == '"') {
        str[len-1] = '\0';
        return str + 1;
    }
    return str;
}

static int mxd_validate_config(mxd_config_t* config) {
    if (!config) return -1;
    
    // Validate port range
    if (config->port < 1024 || config->port > 65535) return -1;
    
    // Validate stake amount
    if (config->initial_stake < 0.0) return -1;
    
    // Validate intervals
    if (config->metrics_interval < 100) return -1;
    
    // Validate network type
    if (strcmp(config->network_type, "mainnet") != 0 && 
        strcmp(config->network_type, "testnet") != 0) return -1;
    
    // Validate bootstrap nodes
    if (config->bootstrap_count > 10) return -1;
    
    return 0;
}

static void mxd_set_default_config(mxd_config_t* config) {
    memset(config, 0, sizeof(mxd_config_t));
    
    // Node identification
    snprintf(config->node_id, sizeof(config->node_id), "node_%lu", (unsigned long)time(NULL));
    strncpy(config->node_name, "MXD Default Node", sizeof(config->node_name) - 1);
    strncpy(config->network_type, "mainnet", sizeof(config->network_type) - 1);
    
    // Basic settings
    config->port = 8000;
    config->initial_stake = 100.0;
    config->metrics_interval = 1000;
    strncpy(config->data_dir, "data", sizeof(config->data_dir) - 1);
    
    // Default bootstrap nodes
    config->bootstrap_count = 2;
    strncpy(config->bootstrap_nodes[0], "127.0.0.1:8001", sizeof(config->bootstrap_nodes[0]) - 1);
    strncpy(config->bootstrap_nodes[1], "127.0.0.1:8002", sizeof(config->bootstrap_nodes[1]) - 1);
    
    // Node data (empty by default)
    strncpy(config->node_data, "", sizeof(config->node_data) - 1);
}

int mxd_load_config(const char* config_file, mxd_config_t* config) {
    // Set default configuration first
    mxd_set_default_config(config);
    
    // If no config file specified, validate and use defaults
    if (config_file == NULL) {
        printf("Using default configuration\n");
        return mxd_validate_config(config);
    }
    
    // Try to open config file
    FILE* fp = fopen(config_file, "r");
    if (!fp) {
        printf("Failed to open config file: %s, using default configuration\n", config_file);
        return mxd_validate_config(config);
    }
    
    char line[1024];
    char key[256], value[768];
    
    while (fgets(line, sizeof(line), fp)) {
        char* trimmed = trim(line);
        if (strlen(trimmed) == 0 || trimmed[0] == '{' || trimmed[0] == '}' || trimmed[0] == ',') {
            continue;
        }
        
        if (sscanf(trimmed, "\"%[^\"]\" : \"%[^\"]\"", key, value) == 2 ||
            sscanf(trimmed, "\"%[^\"]\":%[^,\n]", key, value) == 2) {
            
            char* trimmed_value = trim(value);
            trimmed_value = strip_quotes(trimmed_value);
            
            if (strcmp(key, "node_id") == 0) {
                strncpy(config->node_id, trimmed_value, sizeof(config->node_id) - 1);
            } else if (strcmp(key, "data_dir") == 0) {
                strncpy(config->data_dir, trimmed_value, sizeof(config->data_dir) - 1);
            } else if (strcmp(key, "port") == 0) {
                config->port = (uint16_t)atoi(trimmed_value);
            } else if (strcmp(key, "node_name") == 0) {
                strncpy(config->node_name, trimmed_value, sizeof(config->node_name) - 1);
            } else if (strcmp(key, "node_data") == 0) {
                strncpy(config->node_data, trimmed_value, sizeof(config->node_data) - 1);
            } else if (strcmp(key, "initial_stake") == 0) {
                config->initial_stake = atof(trimmed_value);
            } else if (strcmp(key, "network_type") == 0) {
                strncpy(config->network_type, trimmed_value, sizeof(config->network_type) - 1);
            } else if (strcmp(key, "metrics_interval") == 0) {
                config->metrics_interval = (uint32_t)atoi(trimmed_value);
            } else if (strcmp(key, "bootstrap_nodes") == 0) {
                // Parse bootstrap nodes array
                char* node = strtok(trimmed_value, "[], ");
                config->bootstrap_count = 0;
                while (node != NULL && config->bootstrap_count < 10) {
                    // Remove quotes if present
                    if (node[0] == '"') {
                        node++;
                        node[strlen(node)-1] = '\0';
                    }
                    strncpy(config->bootstrap_nodes[config->bootstrap_count], 
                           node, sizeof(config->bootstrap_nodes[0]) - 1);
                    config->bootstrap_count++;
                    node = strtok(NULL, "[], ");
                }
            }
        }
    }
    
    fclose(fp);
    
    // Validate final configuration
    if (mxd_validate_config(config) != 0) {
        printf("Invalid configuration values, using defaults\n");
        mxd_set_default_config(config);
        return mxd_validate_config(config);
    }
    
    printf("Loaded config: node_id=%s, port=%d, data_dir=%s, node_name=%s\n",
           config->node_id, config->port, config->data_dir, config->node_name);
           
    // Fetch bootstrap nodes from network
    if (mxd_fetch_bootstrap_nodes(config) != 0) {
        printf("Failed to fetch bootstrap nodes, using default configuration\n");
        mxd_set_default_config(config);
        return mxd_validate_config(config);
    }
    
    return 0;
}

int mxd_fetch_bootstrap_nodes(mxd_config_t* config) {
    if (!config) return -1;
    
    printf("Fetching bootstrap nodes from https://mxd.network/bootstrap\n");

    mxd_http_response_t* response = mxd_http_get("https://mxd.network/bootstrap");
    if (!response || response->status_code != 200) {
        // Fall back to hardcoded nodes
        printf("Failed to fetch bootstrap nodes, using fallback nodes\n");
        mxd_http_free_response(response);
        return 0;
    }
    
    cJSON* root = cJSON_Parse(response->data);
    if (!root) {
        printf("Failed to parse bootstrap nodes JSON (error: %s), using fallback nodes\n",
           cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "unknown");
        mxd_http_free_response(response);
        return 0;
    }
    
    cJSON* nodes = cJSON_GetObjectItem(root, "bootstrap_nodes");
    if (!nodes || !cJSON_IsArray(nodes)) {
        printf("Invalid bootstrap nodes format, using fallback nodes\n");
        cJSON_Delete(root);
        mxd_http_free_response(response);
        return 0;
    }
    
    // Start with fresh node list
    config->bootstrap_count = 0;
    
    cJSON* node;
    cJSON_ArrayForEach(node, nodes) {
        if (!cJSON_IsObject(node)) continue;
        
        cJSON* hostname = cJSON_GetObjectItem(node, "hostname");
        cJSON* port = cJSON_GetObjectItem(node, "port");
        
        if (hostname && cJSON_IsString(hostname) && 
            port && cJSON_IsNumber(port)) {
            
            snprintf(config->bootstrap_nodes[config->bootstrap_count],
                    sizeof(config->bootstrap_nodes[0]),
                    "%s:%d",
                    hostname->valuestring,
                    port->valueint);
            
            config->bootstrap_count++;
            if (config->bootstrap_count >= 10) break;  // Max nodes limit
        }
    }
    
    // If no valid nodes found, keep fallback nodes
    if (config->bootstrap_count == 0) {
        printf("No valid bootstrap nodes found, using fallback nodes\n");
        mxd_set_default_config(config);
    } else {
        printf("Loaded %d bootstrap nodes from network\n", config->bootstrap_count);
    }
    
    cJSON_Delete(root);
    mxd_http_free_response(response);
    return 0;
}
