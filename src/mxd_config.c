#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <cjson/cJSON.h>
#include "mxd_config.h"
#include "utils/mxd_http.h"
#include "mxd_logging.h"

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
    strncpy(config->network_type, "testnet", sizeof(config->network_type) - 1);
    
    // Basic settings
    config->port = 8000;
    config->metrics_port = 8080;
    config->initial_stake = 100.0;
    config->metrics_interval = 1000;
    strncpy(config->data_dir, "data", sizeof(config->data_dir) - 1);
    
    // Default bootstrap nodes - will be fetched from API, this is fallback
    config->bootstrap_count = 0;
    
    // Node data (empty by default)
    strncpy(config->node_data, "", sizeof(config->node_data) - 1);
    
    config->enable_upnp = 1;
    config->bootstrap_refresh_interval = 300;
}

int mxd_load_config(const char* config_file, mxd_config_t* config) {
    // Set default configuration first
    mxd_set_default_config(config);
    
    // If no config file specified, validate and use defaults
    if (config_file == NULL) {
        MXD_LOG_INFO("config", "Using default configuration");
        return mxd_validate_config(config);
    }
    
    // Try to open config file
    FILE* fp = fopen(config_file, "r");
    if (!fp) {
        MXD_LOG_WARN("config", "Failed to open config file: %s, using default configuration", config_file);
        if (mxd_fetch_bootstrap_nodes(config) != 0) {
            MXD_LOG_WARN("config", "Failed to fetch bootstrap nodes from network API with defaults");
        } else {
            MXD_LOG_INFO("config", "Successfully fetched %d bootstrap nodes from network API (%s)", 
                         config->bootstrap_count, config->network_type);
        }
        return mxd_validate_config(config);
    }
    
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char* file_contents = malloc(fsize + 1);
    if (!file_contents) {
        fclose(fp);
        MXD_LOG_ERROR("config", "Failed to allocate memory for config file");
        return -1;
    }
    
    size_t read_size = fread(file_contents, 1, fsize, fp);
    file_contents[read_size] = '\0';
    fclose(fp);
    
    cJSON* root = cJSON_Parse(file_contents);
    free(file_contents);
    
    if (!root) {
        MXD_LOG_WARN("config", "Failed to parse config file as JSON, using defaults");
        return mxd_validate_config(config);
    }
    
    cJSON* item;
    
    if ((item = cJSON_GetObjectItem(root, "node_id")) && cJSON_IsString(item)) {
        strncpy(config->node_id, item->valuestring, sizeof(config->node_id) - 1);
    }
    if ((item = cJSON_GetObjectItem(root, "data_dir")) && cJSON_IsString(item)) {
        strncpy(config->data_dir, item->valuestring, sizeof(config->data_dir) - 1);
    }
    if ((item = cJSON_GetObjectItem(root, "port")) && cJSON_IsNumber(item)) {
        config->port = (uint16_t)item->valueint;
    }
    if ((item = cJSON_GetObjectItem(root, "node_name")) && cJSON_IsString(item)) {
        strncpy(config->node_name, item->valuestring, sizeof(config->node_name) - 1);
    }
    if ((item = cJSON_GetObjectItem(root, "node_data")) && cJSON_IsString(item)) {
        strncpy(config->node_data, item->valuestring, sizeof(config->node_data) - 1);
    }
    if ((item = cJSON_GetObjectItem(root, "initial_stake")) && cJSON_IsNumber(item)) {
        config->initial_stake = item->valuedouble;
    }
    if ((item = cJSON_GetObjectItem(root, "network_type")) && cJSON_IsString(item)) {
        strncpy(config->network_type, item->valuestring, sizeof(config->network_type) - 1);
    }
    
    cJSON* metrics = cJSON_GetObjectItem(root, "metrics");
    if (metrics && cJSON_IsObject(metrics)) {
        if ((item = cJSON_GetObjectItem(metrics, "update_interval")) && cJSON_IsNumber(item)) {
            config->metrics_interval = (uint32_t)item->valueint;
        }
    }
    
    // Try to get metrics_port from root first, then from metrics object
    if ((item = cJSON_GetObjectItem(root, "metrics_port")) && cJSON_IsNumber(item)) {
        config->metrics_port = (uint16_t)item->valueint;
    } else if (metrics && (item = cJSON_GetObjectItem(metrics, "port")) && cJSON_IsNumber(item)) {
        config->metrics_port = (uint16_t)item->valueint;
    }
    
    // Parse bootstrap_nodes array
    cJSON* bootstrap_nodes = cJSON_GetObjectItem(root, "bootstrap_nodes");
    if (bootstrap_nodes && cJSON_IsArray(bootstrap_nodes)) {
        config->bootstrap_count = 0;
        cJSON* node;
        cJSON_ArrayForEach(node, bootstrap_nodes) {
            if (cJSON_IsString(node) && config->bootstrap_count < 10) {
                strncpy(config->bootstrap_nodes[config->bootstrap_count], 
                       node->valuestring, sizeof(config->bootstrap_nodes[0]) - 1);
                config->bootstrap_count++;
            }
        }
    }
    
    if ((item = cJSON_GetObjectItem(root, "enable_upnp")) && cJSON_IsBool(item)) {
        config->enable_upnp = cJSON_IsTrue(item);
    }
    
    cJSON_Delete(root);
    
    // Validate final configuration
    if (mxd_validate_config(config) != 0) {
        MXD_LOG_WARN("config", "Invalid configuration values, using defaults");
        mxd_set_default_config(config);
        return mxd_validate_config(config);
    }
    
    const char* env_metrics_port = getenv("MXD_METRICS_PORT");
    if (env_metrics_port) {
        int port = atoi(env_metrics_port);
        if (port >= 1024 && port <= 65535) {
            config->metrics_port = (uint16_t)port;
            MXD_LOG_INFO("config", "Metrics port overridden from environment: %d", port);
        }
    }
    
    MXD_LOG_INFO("config", "Loaded config: node_id=%s, port=%d, metrics_port=%d, data_dir=%s, node_name=%s",
           config->node_id, config->port, config->metrics_port, config->data_dir, config->node_name);
    
    if (mxd_fetch_bootstrap_nodes(config) != 0) {
        MXD_LOG_WARN("config", "Failed to fetch bootstrap nodes from network API, will use existing/default nodes and retry later");
    } else {
        MXD_LOG_INFO("config", "Successfully fetched %d bootstrap nodes from network API (%s)", 
                     config->bootstrap_count, config->network_type);
    }
    
    return 0;
}

int mxd_fetch_bootstrap_nodes(mxd_config_t* config) {
    if (!config) return -1;
    
    const char* endpoint = strcmp(config->network_type, "testnet") == 0 
        ? "https://mxd.network/bootstrap/test"
        : "https://mxd.network/bootstrap/main";
    
    MXD_LOG_INFO("config", "Fetching bootstrap nodes from %s", endpoint);

    mxd_http_response_t* response = mxd_http_get(endpoint);
    if (!response || response->status_code != 200) {
        MXD_LOG_ERROR("config", "Failed to fetch bootstrap nodes from %s (status: %d)", 
                      endpoint, response ? response->status_code : 0);
        mxd_http_free_response(response);
        return -1;
    }
    
    cJSON* root = cJSON_Parse(response->data);
    if (!root) {
        MXD_LOG_ERROR("config", "Failed to parse bootstrap nodes JSON response from %s", endpoint);
        mxd_http_free_response(response);
        return -1;
    }
    
    cJSON* nodes = cJSON_GetObjectItem(root, "bootstrap_nodes");
    if (!nodes || !cJSON_IsArray(nodes)) {
        MXD_LOG_ERROR("config", "Invalid bootstrap nodes format in response from %s", endpoint);
        cJSON_Delete(root);
        mxd_http_free_response(response);
        return -1;
    }
    
    // Start with fresh node list
    config->bootstrap_count = 0;
    
    cJSON* node;
    cJSON_ArrayForEach(node, nodes) {
        if (!cJSON_IsObject(node)) continue;
        
        cJSON* ip = cJSON_GetObjectItem(node, "ip");
        cJSON* hostname = cJSON_GetObjectItem(node, "hostname");
        cJSON* port = cJSON_GetObjectItem(node, "port");
        
        const char* address = NULL;
        if (ip && cJSON_IsString(ip)) {
            address = ip->valuestring;
        } else if (hostname && cJSON_IsString(hostname)) {
            address = hostname->valuestring;
        }
        
        int port_num = 0;
        if (port) {
            if (cJSON_IsNumber(port)) {
                port_num = port->valueint;
            } else if (cJSON_IsString(port)) {
                port_num = atoi(port->valuestring);
            }
        }
        
        if (address && port_num > 0) {
            const char* public_ip = getenv("MXD_PUBLIC_IP");
            if (public_ip && strcmp(address, public_ip) == 0 && port_num == config->port) {
                MXD_LOG_DEBUG("config", "Skipping bootstrap node %s:%d (matches our public IP and port)", 
                            address, port_num);
                continue;
            }
            
            snprintf(config->bootstrap_nodes[config->bootstrap_count],
                    sizeof(config->bootstrap_nodes[0]),
                    "%s:%d",
                    address,
                    port_num);
            
            config->bootstrap_count++;
            MXD_LOG_INFO("config", "Added bootstrap node %s:%d", address, port_num);
            if (config->bootstrap_count >= 10) break;
        }
    }
    
    // If no valid nodes found, return error
    if (config->bootstrap_count == 0) {
        MXD_LOG_ERROR("config", "No valid bootstrap nodes found in API response from %s", endpoint);
        cJSON_Delete(root);
        mxd_http_free_response(response);
        return -1;
    }
    
    cJSON* network_info = cJSON_GetObjectItem(root, "network_info");
    if (network_info && cJSON_IsObject(network_info)) {
        cJSON* update_interval = cJSON_GetObjectItem(network_info, "update_interval");
        if (update_interval && cJSON_IsNumber(update_interval)) {
            config->bootstrap_refresh_interval = update_interval->valueint;
            MXD_LOG_INFO("config", "Bootstrap refresh interval: %d seconds", config->bootstrap_refresh_interval);
        }
    }
    
    if (config->bootstrap_refresh_interval == 0) {
        config->bootstrap_refresh_interval = 300;
    }
    
    MXD_LOG_INFO("config", "Loaded %d bootstrap nodes from network", config->bootstrap_count);
    
    cJSON_Delete(root);
    mxd_http_free_response(response);
    return 0;
}
