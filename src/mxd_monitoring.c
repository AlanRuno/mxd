#include "../include/mxd_monitoring.h"
#include "../include/mxd_logging.h"
#include "../include/mxd_address.h"
#include "../include/mxd_transaction.h"
#include "../include/mxd_utxo.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <cjson/cJSON.h>

static mxd_system_metrics_t current_metrics = {0};
static mxd_health_status_t current_health = {0};
static int monitoring_initialized = 0;
static uint16_t metrics_port = 0;
static char prometheus_buffer[4096];
static char health_buffer[1024];
static int server_socket = -1;
static pthread_t server_thread;
static volatile int server_running = 0;

static mxd_wallet_t wallet = {0};
static int wallet_initialized = 0;
static char wallet_response_buffer[8192];
static pthread_mutex_t wallet_mutex = PTHREAD_MUTEX_INITIALIZER;

int mxd_init_monitoring(uint16_t http_port) {
    if (monitoring_initialized) {
        return 0;
    }
    
    metrics_port = http_port;
    memset(&current_metrics, 0, sizeof(current_metrics));
    memset(&current_health, 0, sizeof(current_health));
    
    current_health.is_healthy = 1;
    current_health.database_connected = 1;
    current_health.p2p_active = 1;
    current_health.consensus_active = 1;
    strcpy(current_health.status_message, "System operational");
    current_health.last_check_timestamp = time(NULL);
    
    if (mxd_init_wallet() != 0) {
        MXD_LOG_ERROR("monitoring", "Failed to initialize wallet");
        return -1;
    }
    
    monitoring_initialized = 1;
    MXD_LOG_INFO("monitoring", "Monitoring system initialized on port %d", http_port);
    return 0;
}

void mxd_cleanup_monitoring(void) {
    if (monitoring_initialized) {
        mxd_cleanup_wallet();
        monitoring_initialized = 0;
        MXD_LOG_INFO("monitoring", "Monitoring system cleaned up");
    }
}

int mxd_update_system_metrics(const mxd_system_metrics_t *metrics) {
    if (!monitoring_initialized || !metrics) {
        return -1;
    }
    
    current_metrics = *metrics;
    MXD_LOG_DEBUG("monitoring", "System metrics updated - TPS: %.2f, Peers: %d", 
                  metrics->current_tps, metrics->active_peers);
    return 0;
}

int mxd_get_health_status(mxd_health_status_t *status) {
    if (!monitoring_initialized || !status) {
        return -1;
    }
    
    current_health.last_check_timestamp = time(NULL);
    
    current_health.is_healthy = current_health.database_connected && 
                               current_health.p2p_active && 
                               current_health.consensus_active;
    
    *status = current_health;
    return 0;
}

const char* mxd_get_prometheus_metrics(void) {
    if (!monitoring_initialized) {
        return NULL;
    }
    
    snprintf(prometheus_buffer, sizeof(prometheus_buffer),
        "# HELP mxd_transactions_total Total number of transactions processed\n"
        "# TYPE mxd_transactions_total counter\n"
        "mxd_transactions_total %lu\n"
        "\n"
        "# HELP mxd_blocks_total Total number of blocks processed\n"
        "# TYPE mxd_blocks_total counter\n"
        "mxd_blocks_total %lu\n"
        "\n"
        "# HELP mxd_tps_current Current transactions per second\n"
        "# TYPE mxd_tps_current gauge\n"
        "mxd_tps_current %.2f\n"
        "\n"
        "# HELP mxd_network_latency_ms Network latency in milliseconds\n"
        "# TYPE mxd_network_latency_ms gauge\n"
        "mxd_network_latency_ms %lu\n"
        "\n"
        "# HELP mxd_peers_active Number of active peers\n"
        "# TYPE mxd_peers_active gauge\n"
        "mxd_peers_active %u\n"
        "\n"
        "# HELP mxd_blockchain_height Current blockchain height\n"
        "# TYPE mxd_blockchain_height gauge\n"
        "mxd_blockchain_height %lu\n"
        "\n"
        "# HELP mxd_consensus_efficiency Consensus efficiency percentage\n"
        "# TYPE mxd_consensus_efficiency gauge\n"
        "mxd_consensus_efficiency %.2f\n"
        "\n"
        "# HELP mxd_memory_usage_bytes Memory usage in bytes\n"
        "# TYPE mxd_memory_usage_bytes gauge\n"
        "mxd_memory_usage_bytes %lu\n"
        "\n"
        "# HELP mxd_disk_usage_bytes Disk usage in bytes\n"
        "# TYPE mxd_disk_usage_bytes gauge\n"
        "mxd_disk_usage_bytes %lu\n"
        "\n"
        "# HELP mxd_cpu_usage_percent CPU usage percentage\n"
        "# TYPE mxd_cpu_usage_percent gauge\n"
        "mxd_cpu_usage_percent %.2f\n",
        current_metrics.total_transactions,
        current_metrics.total_blocks,
        current_metrics.current_tps,
        current_metrics.network_latency_ms,
        current_metrics.active_peers,
        current_metrics.blockchain_height,
        current_metrics.consensus_efficiency,
        current_metrics.memory_usage_bytes,
        current_metrics.disk_usage_bytes,
        current_metrics.cpu_usage_percent
    );
    
    return prometheus_buffer;
}

const char* mxd_get_health_json(void) {
    if (!monitoring_initialized) {
        return NULL;
    }
    
    snprintf(health_buffer, sizeof(health_buffer),
        "{"
        "\"status\":\"%s\","
        "\"timestamp\":%lu,"
        "\"checks\":{"
        "\"database\":%s,"
        "\"p2p\":%s,"
        "\"consensus\":%s"
        "},"
        "\"message\":\"%s\""
        "}",
        current_health.is_healthy ? "healthy" : "unhealthy",
        current_health.last_check_timestamp,
        current_health.database_connected ? "true" : "false",
        current_health.p2p_active ? "true" : "false",
        current_health.consensus_active ? "true" : "false",
        current_health.status_message
    );
    
    return health_buffer;
}

int mxd_init_wallet(void) {
    if (wallet_initialized) {
        MXD_LOG_INFO("wallet", "Wallet already initialized");
        return 0;
    }
    
    MXD_LOG_INFO("wallet", "Starting wallet initialization...");
    memset(&wallet, 0, sizeof(wallet));
    
    MXD_LOG_INFO("wallet", "Attempting to initialize UTXO database...");
    if (mxd_init_utxo_db("wallet_utxo.db") != 0) {
        MXD_LOG_ERROR("wallet", "Failed to initialize wallet UTXO database");
        MXD_LOG_WARN("wallet", "Continuing without UTXO database for wallet functionality");
    } else {
        MXD_LOG_INFO("wallet", "UTXO database initialized successfully");
    }
    
    wallet_initialized = 1;
    MXD_LOG_INFO("wallet", "Wallet system initialized");
    return 0;
}

void mxd_cleanup_wallet(void) {
    if (wallet_initialized) {
        pthread_mutex_lock(&wallet_mutex);
        memset(&wallet, 0, sizeof(wallet));
        wallet_initialized = 0;
        pthread_mutex_unlock(&wallet_mutex);
        MXD_LOG_INFO("wallet", "Wallet system cleaned up");
    }
}

const char* mxd_get_wallet_html(void) {
    static const char* wallet_html = 
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "    <meta charset=\"UTF-8\">\n"
        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        "    <title>MXD Web3 Wallet</title>\n"
        "    <style>\n"
        "        * { margin: 0; padding: 0; box-sizing: border-box; }\n"
        "        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }\n"
        "        .container { max-width: 1200px; margin: 0 auto; }\n"
        "        .header { text-align: center; color: white; margin-bottom: 30px; }\n"
        "        .header h1 { font-size: 2.5rem; margin-bottom: 10px; }\n"
        "        .header p { font-size: 1.1rem; opacity: 0.9; }\n"
        "        .wallet-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 20px; }\n"
        "        .card { background: white; border-radius: 15px; padding: 25px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }\n"
        "        .card h2 { color: #333; margin-bottom: 20px; font-size: 1.5rem; }\n"
        "        .form-group { margin-bottom: 15px; }\n"
        "        .form-group label { display: block; margin-bottom: 5px; color: #555; font-weight: 500; }\n"
        "        .form-group input, .form-group textarea { width: 100%; padding: 12px; border: 2px solid #e1e5e9; border-radius: 8px; font-size: 14px; transition: border-color 0.3s; }\n"
        "        .form-group input:focus, .form-group textarea:focus { outline: none; border-color: #667eea; }\n"
        "        .btn { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 12px 24px; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 500; transition: transform 0.2s; }\n"
        "        .btn:hover { transform: translateY(-2px); }\n"
        "        .btn:active { transform: translateY(0); }\n"
        "        .address-item { background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 10px; border-left: 4px solid #667eea; }\n"
        "        .address-item .address { font-family: monospace; font-size: 12px; color: #666; word-break: break-all; }\n"
        "        .address-item .balance { font-weight: bold; color: #333; margin-top: 5px; }\n"
        "        .status { padding: 10px; border-radius: 8px; margin-top: 15px; }\n"
        "        .status.success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }\n"
        "        .status.error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }\n"
        "        .status.info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }\n"
        "        @media (max-width: 768px) { .wallet-grid { grid-template-columns: 1fr; } .header h1 { font-size: 2rem; } }\n"
        "    </style>\n"
        "</head>\n"
        "<body>\n"
        "    <div class=\"container\">\n"
        "        <div class=\"header\">\n"
        "            <h1>MXD Web3 Wallet</h1>\n"
        "            <p>Manage your MXD addresses, check balances, and send transactions</p>\n"
        "        </div>\n"
        "        <div class=\"wallet-grid\">\n"
        "            <div class=\"card\">\n"
        "                <h2>Generate New Address</h2>\n"
        "                <div class=\"form-group\">\n"
        "                    <label for=\"passphrase\">Passphrase (optional):</label>\n"
        "                    <input type=\"password\" id=\"passphrase\" placeholder=\"Enter passphrase for key derivation\">\n"
        "                </div>\n"
        "                <button class=\"btn\" onclick=\"generateAddress()\">Generate Address</button>\n"
        "                <div id=\"generateStatus\"></div>\n"
        "            </div>\n"
        "            <div class=\"card\">\n"
        "                <h2>Check Balance</h2>\n"
        "                <div class=\"form-group\">\n"
        "                    <label for=\"balanceAddress\">Address:</label>\n"
        "                    <input type=\"text\" id=\"balanceAddress\" placeholder=\"Enter MXD address\">\n"
        "                </div>\n"
        "                <button class=\"btn\" onclick=\"checkBalance()\">Check Balance</button>\n"
        "                <div id=\"balanceStatus\"></div>\n"
        "            </div>\n"
        "            <div class=\"card\">\n"
        "                <h2>Send Transaction</h2>\n"
        "                <div class=\"form-group\">\n"
        "                    <label for=\"sendFrom\">From Address:</label>\n"
        "                    <input type=\"text\" id=\"sendFrom\" placeholder=\"Your address\">\n"
        "                </div>\n"
        "                <div class=\"form-group\">\n"
        "                    <label for=\"sendTo\">To Address:</label>\n"
        "                    <input type=\"text\" id=\"sendTo\" placeholder=\"Recipient address\">\n"
        "                </div>\n"
        "                <div class=\"form-group\">\n"
        "                    <label for=\"sendAmount\">Amount:</label>\n"
        "                    <input type=\"number\" id=\"sendAmount\" placeholder=\"Amount to send\" step=\"0.00000001\">\n"
        "                </div>\n"
        "                <button class=\"btn\" onclick=\"sendTransaction()\">Send Transaction</button>\n"
        "                <div id=\"sendStatus\"></div>\n"
        "            </div>\n"
        "            <div class=\"card\">\n"
        "                <h2>My Addresses</h2>\n"
        "                <div id=\"addressList\">\n"
        "                    <p style=\"color: #666; text-align: center; padding: 20px;\">No addresses generated yet</p>\n"
        "                </div>\n"
        "                <button class=\"btn\" onclick=\"refreshAddresses()\">Refresh Balances</button>\n"
        "            </div>\n"
        "        </div>\n"
        "    </div>\n"
        "    <script>\n"
        "        let addresses = [];\n"
        "        function showStatus(elementId, message, type) {\n"
        "            const element = document.getElementById(elementId);\n"
        "            element.innerHTML = '<div class=\"status ' + type + '\">' + message + '</div>';\n"
        "        }\n"
        "        async function generateAddress() {\n"
        "            const passphrase = document.getElementById('passphrase').value;\n"
        "            showStatus('generateStatus', 'Generating address...', 'info');\n"
        "            try {\n"
        "                const response = await fetch('/wallet/generate', {\n"
        "                    method: 'POST',\n"
        "                    headers: { 'Content-Type': 'application/json' },\n"
        "                    body: JSON.stringify({ passphrase: passphrase })\n"
        "                });\n"
        "                const data = await response.json();\n"
        "                if (data.success) {\n"
        "                    addresses.push(data.address);\n"
        "                    showStatus('generateStatus', 'Address generated: ' + data.address, 'success');\n"
        "                    updateAddressList();\n"
        "                    document.getElementById('passphrase').value = '';\n"
        "                } else {\n"
        "                    showStatus('generateStatus', 'Error: ' + data.error, 'error');\n"
        "                }\n"
        "            } catch (error) {\n"
        "                showStatus('generateStatus', 'Network error: ' + error.message, 'error');\n"
        "            }\n"
        "        }\n"
        "        async function checkBalance() {\n"
        "            const address = document.getElementById('balanceAddress').value;\n"
        "            if (!address) {\n"
        "                showStatus('balanceStatus', 'Please enter an address', 'error');\n"
        "                return;\n"
        "            }\n"
        "            showStatus('balanceStatus', 'Checking balance...', 'info');\n"
        "            try {\n"
        "                const response = await fetch('/wallet/balance?address=' + encodeURIComponent(address));\n"
        "                const data = await response.json();\n"
        "                if (data.success) {\n"
        "                    showStatus('balanceStatus', 'Balance: ' + data.balance + ' MXD', 'success');\n"
        "                } else {\n"
        "                    showStatus('balanceStatus', 'Error: ' + data.error, 'error');\n"
        "                }\n"
        "            } catch (error) {\n"
        "                showStatus('balanceStatus', 'Network error: ' + error.message, 'error');\n"
        "            }\n"
        "        }\n"
        "        async function sendTransaction() {\n"
        "            const from = document.getElementById('sendFrom').value;\n"
        "            const to = document.getElementById('sendTo').value;\n"
        "            const amount = document.getElementById('sendAmount').value;\n"
        "            if (!from || !to || !amount) {\n"
        "                showStatus('sendStatus', 'Please fill in all fields', 'error');\n"
        "                return;\n"
        "            }\n"
        "            showStatus('sendStatus', 'Creating transaction...', 'info');\n"
        "            try {\n"
        "                const response = await fetch('/wallet/send', {\n"
        "                    method: 'POST',\n"
        "                    headers: { 'Content-Type': 'application/json' },\n"
        "                    body: JSON.stringify({ from: from, to: to, amount: amount })\n"
        "                });\n"
        "                const data = await response.json();\n"
        "                if (data.success) {\n"
        "                    showStatus('sendStatus', 'Transaction sent! TX ID: ' + data.txid, 'success');\n"
        "                    document.getElementById('sendFrom').value = '';\n"
        "                    document.getElementById('sendTo').value = '';\n"
        "                    document.getElementById('sendAmount').value = '';\n"
        "                } else {\n"
        "                    showStatus('sendStatus', 'Error: ' + data.error, 'error');\n"
        "                }\n"
        "            } catch (error) {\n"
        "                showStatus('sendStatus', 'Network error: ' + error.message, 'error');\n"
        "            }\n"
        "        }\n"
        "        async function refreshAddresses() {\n"
        "            updateAddressList();\n"
        "        }\n"
        "        async function updateAddressList() {\n"
        "            const listElement = document.getElementById('addressList');\n"
        "            if (addresses.length === 0) {\n"
        "                listElement.innerHTML = '<p style=\"color: #666; text-align: center; padding: 20px;\">No addresses generated yet</p>';\n"
        "                return;\n"
        "            }\n"
        "            let html = '';\n"
        "            for (const address of addresses) {\n"
        "                try {\n"
        "                    const response = await fetch('/wallet/balance?address=' + encodeURIComponent(address));\n"
        "                    const data = await response.json();\n"
        "                    const balance = data.success ? data.balance : 'Error';\n"
        "                    html += '<div class=\"address-item\"><div class=\"address\">' + address + '</div><div class=\"balance\">Balance: ' + balance + ' MXD</div></div>';\n"
        "                } catch (error) {\n"
        "                    html += '<div class=\"address-item\"><div class=\"address\">' + address + '</div><div class=\"balance\">Balance: Error loading</div></div>';\n"
        "                }\n"
        "            }\n"
        "            listElement.innerHTML = html;\n"
        "        }\n"
        "        window.onload = function() {\n"
        "            updateAddressList();\n"
        "        };\n"
        "    </script>\n"
        "</body>\n"
        "</html>";
    
    return wallet_html;
}

const char* mxd_handle_wallet_generate(void) {
    if (!wallet_initialized) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Wallet not initialized\"}");
        return wallet_response_buffer;
    }
    
    pthread_mutex_lock(&wallet_mutex);
    
    if (wallet.keypair_count >= 10) {
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Maximum number of addresses reached\"}");
        return wallet_response_buffer;
    }
    
    mxd_wallet_keypair_t* keypair = &wallet.keypairs[wallet.keypair_count];
    
    uint8_t property_key[64];
    uint8_t public_key[256];
    uint8_t private_key[128];
    char address[64];
    char passphrase[256];
    
    if (mxd_generate_passphrase(passphrase, sizeof(passphrase)) != 0) {
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to generate passphrase\"}");
        return wallet_response_buffer;
    }
    
    if (mxd_derive_property_key(passphrase, "", property_key) != 0) {
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to derive property key\"}");
        return wallet_response_buffer;
    }
    
    if (mxd_generate_keypair(property_key, public_key, private_key) != 0) {
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to generate keypair\"}");
        return wallet_response_buffer;
    }
    
    if (mxd_generate_address(public_key, address, sizeof(address)) != 0) {
        pthread_mutex_unlock(&wallet_mutex);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to generate address\"}");
        return wallet_response_buffer;
    }
    
    strncpy(keypair->address, address, sizeof(keypair->address) - 1);
    memcpy(keypair->public_key, public_key, sizeof(public_key));
    memcpy(keypair->private_key, private_key, sizeof(private_key));
    strncpy(keypair->passphrase, passphrase, sizeof(keypair->passphrase) - 1);
    
    wallet.keypair_count++;
    
    pthread_mutex_unlock(&wallet_mutex);
    
    snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
        "{\"success\":true,\"address\":\"%s\"}", address);
    return wallet_response_buffer;
}

const char* mxd_handle_wallet_balance(const char* address) {
    if (!wallet_initialized || !address) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid request\"}");
        return wallet_response_buffer;
    }
    
    if (mxd_validate_address(address) != 0) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid address format\"}");
        return wallet_response_buffer;
    }
    
    pthread_mutex_lock(&wallet_mutex);
    
    uint8_t* public_key = NULL;
    for (size_t i = 0; i < wallet.keypair_count; i++) {
        if (strcmp(wallet.keypairs[i].address, address) == 0) {
            public_key = wallet.keypairs[i].public_key;
            break;
        }
    }
    
    pthread_mutex_unlock(&wallet_mutex);
    
    if (!public_key) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Address not found in wallet\"}");
        return wallet_response_buffer;
    }
    
    double balance = mxd_get_balance(public_key);
    
    snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
        "{\"success\":true,\"balance\":%.8f}", balance);
    return wallet_response_buffer;
}

const char* mxd_handle_wallet_send(const char* recipient, const char* amount) {
    if (!wallet_initialized || !recipient || !amount) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid request parameters\"}");
        return wallet_response_buffer;
    }
    
    double amount_value = strtod(amount, NULL);
    if (amount_value <= 0) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid amount\"}");
        return wallet_response_buffer;
    }
    
    if (mxd_validate_address(recipient) != 0) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Invalid recipient address\"}");
        return wallet_response_buffer;
    }
    
    pthread_mutex_lock(&wallet_mutex);
    
    uint8_t* recipient_pubkey = NULL;
    for (size_t i = 0; i < wallet.keypair_count; i++) {
        if (strcmp(wallet.keypairs[i].address, recipient) == 0) {
            recipient_pubkey = wallet.keypairs[i].public_key;
            break;
        }
    }
    
    pthread_mutex_unlock(&wallet_mutex);
    
    if (!recipient_pubkey) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Recipient address not found\"}");
        return wallet_response_buffer;
    }
    
    mxd_transaction_t tx;
    if (mxd_create_transaction(&tx) != 0) {
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to create transaction\"}");
        return wallet_response_buffer;
    }
    
    if (mxd_add_tx_output(&tx, recipient_pubkey, amount_value) != 0) {
        mxd_free_transaction(&tx);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to add transaction output\"}");
        return wallet_response_buffer;
    }
    
    uint8_t tx_hash[64];
    if (mxd_calculate_tx_hash(&tx, tx_hash) != 0) {
        mxd_free_transaction(&tx);
        snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
            "{\"success\":false,\"error\":\"Failed to calculate transaction hash\"}");
        return wallet_response_buffer;
    }
    
    char tx_hash_str[129];
    for (int i = 0; i < 64; i++) {
        snprintf(tx_hash_str + (i * 2), 3, "%02x", tx_hash[i]);
    }
    tx_hash_str[128] = '\0';
    
    mxd_free_transaction(&tx);
    
    snprintf(wallet_response_buffer, sizeof(wallet_response_buffer),
        "{\"success\":true,\"txid\":\"%s\"}", tx_hash_str);
    return wallet_response_buffer;
}

static void handle_http_request(int client_socket) {
    char buffer[2048];
    ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        close(client_socket);
        return;
    }
    
    buffer[bytes_read] = '\0';
    
    char method[16], path[256], version[16];
    if (sscanf(buffer, "%15s %255s %15s", method, path, version) != 3) {
        close(client_socket);
        return;
    }
    
    const char* response_body = NULL;
    const char* content_type = "text/plain";
    int status_code = 404;
    
    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/health") == 0) {
            response_body = mxd_get_health_json();
            content_type = "application/json";
            status_code = 200;
        } else if (strcmp(path, "/metrics") == 0) {
            response_body = mxd_get_prometheus_metrics();
            content_type = "text/plain";
            status_code = 200;
        } else if (strcmp(path, "/wallet") == 0) {
            response_body = mxd_get_wallet_html();
            content_type = "text/html";
            status_code = 200;
        } else if (strncmp(path, "/wallet/balance?address=", 24) == 0) {
            char* address = path + 24;
            char decoded_address[256];
            int j = 0;
            for (int i = 0; address[i] && j < sizeof(decoded_address) - 1; i++) {
                if (address[i] == '%' && address[i+1] && address[i+2]) {
                    char hex[3] = {address[i+1], address[i+2], '\0'};
                    decoded_address[j++] = (char)strtol(hex, NULL, 16);
                    i += 2;
                } else {
                    decoded_address[j++] = address[i];
                }
            }
            decoded_address[j] = '\0';
            response_body = mxd_handle_wallet_balance(decoded_address);
            content_type = "application/json";
            status_code = 200;
        }
    } else if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/wallet/generate") == 0) {
            response_body = mxd_handle_wallet_generate();
            content_type = "application/json";
            status_code = 200;
        } else if (strcmp(path, "/wallet/send") == 0) {
            char* body_start = strstr(buffer, "\r\n\r\n");
            if (body_start) {
                body_start += 4;
                cJSON* json = cJSON_Parse(body_start);
                if (json) {
                    cJSON* to = cJSON_GetObjectItem(json, "to");
                    cJSON* amount = cJSON_GetObjectItem(json, "amount");
                    if (to && amount && cJSON_IsString(to) && cJSON_IsString(amount)) {
                        response_body = mxd_handle_wallet_send(to->valuestring, amount->valuestring);
                        content_type = "application/json";
                        status_code = 200;
                    }
                    cJSON_Delete(json);
                }
            }
            if (!response_body) {
                response_body = "{\"success\":false,\"error\":\"Invalid request body\"}";
                content_type = "application/json";
                status_code = 400;
            }
        }
    }
    
    if (!response_body) {
        response_body = "Not Found";
        status_code = 404;
    }
    
    char response[16384];
    int response_len = snprintf(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "\r\n"
        "%s",
        status_code,
        status_code == 200 ? "OK" : (status_code == 400 ? "Bad Request" : "Not Found"),
        content_type,
        strlen(response_body),
        response_body);
    
    send(client_socket, response, response_len, 0);
    close(client_socket);
}

static void* server_thread_func(void* arg) {
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (client_socket < 0) {
            if (server_running && errno != EINTR) {
                MXD_LOG_ERROR("monitoring", "Accept failed: %s", strerror(errno));
            }
            continue;
        }
        
        handle_http_request(client_socket);
    }
    return NULL;
}

int mxd_start_metrics_server(void) {
    if (!monitoring_initialized) {
        return -1;
    }
    
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        MXD_LOG_ERROR("monitoring", "Failed to create socket: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        MXD_LOG_WARN("monitoring", "Failed to set SO_REUSEADDR: %s", strerror(errno));
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(metrics_port);
    
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        MXD_LOG_ERROR("monitoring", "Failed to bind to port %d: %s", metrics_port, strerror(errno));
        close(server_socket);
        server_socket = -1;
        return -1;
    }
    
    if (listen(server_socket, 5) < 0) {
        MXD_LOG_ERROR("monitoring", "Failed to listen on socket: %s", strerror(errno));
        close(server_socket);
        server_socket = -1;
        return -1;
    }
    
    server_running = 1;
    pthread_attr_t server_attr;
    pthread_attr_init(&server_attr);
    pthread_attr_setstacksize(&server_attr, 512 * 1024); // 512KB stack
    if (pthread_create(&server_thread, &server_attr, server_thread_func, NULL) != 0) {
        MXD_LOG_ERROR("monitoring", "Failed to create server thread: %s", strerror(errno));
        pthread_attr_destroy(&server_attr);
        close(server_socket);
        server_socket = -1;
        server_running = 0;
        return -1;
    }
    pthread_attr_destroy(&server_attr);
    
    MXD_LOG_INFO("monitoring", "Metrics server started on port %d", metrics_port);
    MXD_LOG_INFO("monitoring", "Endpoints: /metrics (Prometheus), /health (JSON)");
    return 0;
}

int mxd_stop_metrics_server(void) {
    if (!monitoring_initialized || !server_running) {
        return -1;
    }
    
    server_running = 0;
    
    if (server_socket >= 0) {
        close(server_socket);
        server_socket = -1;
    }
    
    pthread_join(server_thread, NULL);
    
    MXD_LOG_INFO("monitoring", "Metrics server stopped");
    return 0;
}
