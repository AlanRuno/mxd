Supply Chain Security Additions
- SBOMs: CI generates CycloneDX SBOMs for both source and the Docker image and uploads them as artifacts.
- Container signing: Tag-gated GHCR publish job signs images with cosign (keyless). Signing is non-blocking to accommodate permission differences.
- Scanning: Trivy vulnerability scan runs in CI with SARIF upload retained; non-blocking on PRs.
- Secret handling: No secrets committed; GITHUB_TOKEN used for GHCR with least privileges in tag jobs.
- Logging policy: Ensure no sensitive keys or raw secrets are logged; validation tests print only synthetic or masked data.


# MXD Library Security Guidelines

## Overview
This document outlines the security guidelines and best practices for developing and maintaining the MXD Library. Following these guidelines is mandatory for all contributors and is critical for achieving enterprise production readiness.

## Security Status (August 2025)
Following comprehensive security audit, critical security vulnerabilities have been resolved through implementation of secure logging framework and environment-based secrets management.

## 🚨 CRITICAL SECURITY RULES

### 1. NO DEBUG OUTPUT OF SENSITIVE DATA
**RULE**: Never use printf, fprintf, or any direct output functions to print sensitive information.

#### ❌ FORBIDDEN - Examples of what NOT to do:
```c
// NEVER do this - exposes private keys
printf("Private key: ");
for (int i = 0; i < 32; i++) {
    printf("%02x", private_key[i]);
}

// NEVER do this - exposes hash operations
printf("SHA-256 hash: %s\n", hash_output);

// NEVER do this - exposes network information
printf("Peer IP: %s, Status: %d\n", peer_ip, peer_status);

// NEVER do this - exposes transaction data
printf("Transaction amount: %.8f MXD\n", tx_amount);
```

#### ✅ CORRECT - Use secure logging instead:
```c
// Use structured logging without sensitive data
MXD_LOG_INFO("crypto", "Hash operation completed successfully");
MXD_LOG_DEBUG("network", "Peer connection established");
MXD_LOG_INFO("transaction", "Transaction validation completed");

// For debugging, use conditional compilation
#ifdef MXD_DEBUG_BUILD
MXD_LOG_DEBUG("crypto", "Hash operation debug info (non-sensitive)");
#endif
```

### 2. NO HARDCODED SECURITY PARAMETERS
**RULE**: Never hardcode security-critical values in source code.

#### ❌ FORBIDDEN - Examples of what NOT to do:
```c
// NEVER hardcode network magic numbers
uint32_t network_magic = 0x4D584431;

// NEVER hardcode cryptographic salts
char salt[] = "MXDKeyDerivation";

// NEVER hardcode default keys or passwords
char default_key[] = "default_encryption_key_123";

// NEVER hardcode API keys or tokens
char api_key[] = "sk_live_abcd1234567890";
```

#### ✅ CORRECT - Use environment variables and secure loading:
```c
// Load from environment with validation
uint32_t network_magic;
if (mxd_load_secret_from_env("MXD_NETWORK_MAGIC", &network_magic, sizeof(network_magic)) != 0) {
    MXD_LOG_ERROR("config", "Failed to load network magic from environment");
    return -1;
}

// Generate random salts for new deployments
uint8_t salt[32];
if (mxd_generate_random_salt(salt, sizeof(salt)) != 0) {
    MXD_LOG_ERROR("crypto", "Failed to generate random salt");
    return -1;
}

// Use secure secret management
const char* api_key = mxd_vault_get_secret("api_key");
if (!api_key) {
    MXD_LOG_ERROR("auth", "Failed to retrieve API key from vault");
    return -1;
}
```

### 3. SECURE MEMORY MANAGEMENT
**RULE**: Always handle sensitive data in memory securely.

#### ✅ REQUIRED - Secure memory practices:
```c
// Always zero sensitive memory before freeing
void cleanup_private_key(uint8_t* private_key, size_t size) {
    if (private_key) {
        mxd_secure_zero(private_key, size);  // Use secure zero function
        free(private_key);
    }
}

// Use secure allocation for sensitive data
uint8_t* private_key = mxd_secure_alloc(32);
if (!private_key) {
    return -1;
}
// ... use private key ...
mxd_secure_free(private_key, 32);  // Automatically zeros before freeing

// Always check buffer bounds
int copy_address(char* dest, size_t dest_size, const char* src) {
    if (!dest || !src || dest_size == 0) {
        return -1;
    }
    
    size_t src_len = strlen(src);
    if (src_len >= dest_size) {
        MXD_LOG_ERROR("address", "Address too long for buffer");
        return -1;
    }
    
    memcpy(dest, src, src_len);
    dest[src_len] = '\0';
    return 0;
}
```

### 4. INPUT VALIDATION
**RULE**: Validate all inputs, especially from network and user sources.

#### ✅ REQUIRED - Input validation patterns:
```c
// Validate network message size
int process_network_message(const void* data, size_t size) {
    if (!data || size == 0 || size > MAX_MESSAGE_SIZE) {
        MXD_LOG_ERROR("network", "Invalid message size: %zu", size);
        return -1;
    }
    
    // Validate message structure
    if (!mxd_validate_message_structure(data, size)) {
        MXD_LOG_ERROR("network", "Invalid message structure");
        return -1;
    }
    
    // Process validated message
    return process_validated_message(data, size);
}

// Validate transaction inputs
int validate_transaction(const mxd_transaction_t* tx) {
    if (!tx) {
        return -1;
    }
    
    // Validate transaction version
    if (tx->version != MXD_TX_VERSION) {
        MXD_LOG_ERROR("transaction", "Invalid transaction version: %d", tx->version);
        return -1;
    }
    
    // Validate input/output counts
    if (tx->input_count > MXD_MAX_TX_INPUTS || tx->output_count > MXD_MAX_TX_OUTPUTS) {
        MXD_LOG_ERROR("transaction", "Invalid input/output count");
        return -1;
    }
    
    // Validate amounts
    if (tx->voluntary_tip < 0) {
        MXD_LOG_ERROR("transaction", "Invalid voluntary tip amount");
        return -1;
    }
    
    return 0;
}
```

## 🔍 SECURITY REVIEW CHECKLIST

### Before Committing Code
- [ ] No printf/fprintf statements exposing sensitive data
- [ ] No hardcoded security parameters (keys, salts, magic numbers)
- [ ] All sensitive memory is securely zeroed before freeing
- [ ] All inputs are validated with proper bounds checking
- [ ] Error messages don't expose sensitive information
- [ ] Logging uses MXD_LOG_* macros instead of direct output
- [ ] Debug code is conditionally compiled (#ifdef MXD_DEBUG_BUILD)

### Code Review Requirements
- [ ] Security-focused code review by senior developer
- [ ] Static analysis tools pass (cppcheck, clang-tidy)
- [ ] Security tests pass
- [ ] No new security warnings in CI/CD pipeline

## 🛡️ SECURE CODING PATTERNS

### Logging Best Practices
```c
// ✅ GOOD - Structured logging without sensitive data
MXD_LOG_INFO("auth", "User authentication successful", 
             "user_id", user_id, "timestamp", current_time);

// ✅ GOOD - Error logging without exposing details
MXD_LOG_ERROR("crypto", "Signature verification failed");

// ❌ BAD - Exposing sensitive data
MXD_LOG_DEBUG("crypto", "Private key: %s", private_key_hex);

// ❌ BAD - Exposing internal details
MXD_LOG_ERROR("auth", "Authentication failed for password: %s", password);
```

### Error Handling Patterns
```c
// ✅ GOOD - Secure error handling
int mxd_verify_signature(const uint8_t* signature, const uint8_t* message, const uint8_t* public_key) {
    if (!signature || !message || !public_key) {
        MXD_LOG_ERROR("crypto", "Invalid parameters for signature verification");
        return MXD_ERROR_INVALID_PARAMS;
    }
    
    // Perform verification
    int result = crypto_verify_signature(signature, message, public_key);
    
    if (result == 0) {
        MXD_LOG_DEBUG("crypto", "Signature verification successful");
        return MXD_SUCCESS;
    } else {
        MXD_LOG_ERROR("crypto", "Signature verification failed");
        return MXD_ERROR_VERIFICATION_FAILED;
    }
}

// ❌ BAD - Exposing sensitive data in errors
int bad_verify_signature(const uint8_t* signature, const uint8_t* message, const uint8_t* public_key) {
    printf("Verifying signature: ");
    for (int i = 0; i < 64; i++) printf("%02x", signature[i]);  // NEVER DO THIS
    printf("\n");
    
    // ... verification code ...
    
    if (result != 0) {
        printf("Verification failed for public key: ");
        for (int i = 0; i < 32; i++) printf("%02x", public_key[i]);  // NEVER DO THIS
        printf("\n");
    }
}
```

### Configuration Security
```c
// ✅ GOOD - Secure configuration loading
typedef struct {
    uint32_t network_magic;
    uint8_t crypto_salt[32];
    char bootstrap_nodes[10][256];
    // ... other config fields
} mxd_config_t;

int mxd_load_secure_config(mxd_config_t* config) {
    // Load from environment with fallbacks
    if (mxd_load_secret_from_env("MXD_NETWORK_MAGIC", &config->network_magic, sizeof(config->network_magic)) != 0) {
        // Generate random network magic for development
        if (mxd_generate_random_bytes(&config->network_magic, sizeof(config->network_magic)) != 0) {
            MXD_LOG_ERROR("config", "Failed to generate network magic");
            return -1;
        }
        MXD_LOG_WARN("config", "Using generated network magic for development");
    }
    
    // Load crypto salt securely
    if (mxd_load_secret_from_env("MXD_CRYPTO_SALT", config->crypto_salt, sizeof(config->crypto_salt)) != 0) {
        if (mxd_generate_random_salt(config->crypto_salt, sizeof(config->crypto_salt)) != 0) {
            MXD_LOG_ERROR("config", "Failed to generate crypto salt");
            return -1;
        }
        MXD_LOG_WARN("config", "Using generated crypto salt for development");
    }
    
    return 0;
}
```

## 🚨 INCIDENT RESPONSE

### If Security Issue Discovered
1. **Immediate**: Stop all development and deployment
2. **Assess**: Determine scope and impact of the security issue
3. **Fix**: Implement immediate fix following security guidelines
4. **Test**: Comprehensive security testing of the fix
5. **Review**: Security team review before deployment
6. **Document**: Update security guidelines if needed

### Security Contact
- **Security Team**: security@mxd.network
- **Emergency**: Create GitHub issue with "SECURITY" label
- **Internal**: Slack #security-alerts channel

## 📚 ADDITIONAL RESOURCES

### Security Tools
- **Static Analysis**: cppcheck, clang-tidy (integrated in CI/CD)
- **Dynamic Analysis**: Valgrind (memory leak detection)
- **Security Scanning**: Trivy (vulnerability scanning)
- **Secrets Detection**: git-secrets, truffleHog

### Security Training
- **OWASP Top 10**: Understanding common vulnerabilities
- **Secure Coding**: C/C++ secure programming practices
- **Cryptography**: Proper use of cryptographic libraries
- **Incident Response**: Security incident handling procedures

### Documentation
- **Security Architecture**: `docs/SECURITY_ARCHITECTURE.md`
- **Threat Model**: `docs/THREAT_MODEL.md`
- **Audit Reports**: `docs/security/audit_reports/`
- **Penetration Test Results**: `docs/security/pentest_reports/`

---

**Document Version**: 1.0 (Post-Audit)
**Last Updated**: August 1, 2025
**Next Review**: Monthly during development, quarterly in production
**Owner**: Security Team
**Approver**: Chief Security Officer

**REMEMBER**: Security is everyone's responsibility. When in doubt, ask the security team.
