#include "mxd_types.h"
#include "mxd_logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

int mxd_parse_amount(const char *str, mxd_amount_t *amount) {
    if (!str || !amount) {
        return -1;
    }

    while (isspace(*str)) {
        str++;
    }

    if (*str == '\0') {
        return -1;
    }

    uint64_t whole = 0;
    const char *p = str;
    
    while (isdigit(*p)) {
        uint64_t digit = *p - '0';
        
        if (whole > (UINT64_MAX - digit) / 10) {
            MXD_LOG_ERROR("amount", "Amount overflow in whole part");
            return -1;
        }
        
        whole = whole * 10 + digit;
        p++;
    }

    uint64_t fractional = 0;
    int decimal_places = 0;
    
    if (*p == '.') {
        p++;
        
        while (isdigit(*p) && decimal_places < MXD_AMOUNT_DECIMALS) {
            fractional = fractional * 10 + (*p - '0');
            decimal_places++;
            p++;
        }
        
        while (isdigit(*p)) {
            p++;
        }
    }

    while (isspace(*p)) {
        p++;
    }

    if (*p != '\0') {
        MXD_LOG_ERROR("amount", "Invalid characters in amount string");
        return -1;
    }

    while (decimal_places < MXD_AMOUNT_DECIMALS) {
        fractional *= 10;
        decimal_places++;
    }

    if (whole > MXD_AMOUNT_MAX / MXD_AMOUNT_MULTIPLIER) {
        MXD_LOG_ERROR("amount", "Amount overflow when converting to base units");
        return -1;
    }

    uint64_t whole_in_base_units = whole * MXD_AMOUNT_MULTIPLIER;
    
    if (whole_in_base_units > MXD_AMOUNT_MAX - fractional) {
        MXD_LOG_ERROR("amount", "Amount overflow when adding fractional part");
        return -1;
    }

    *amount = whole_in_base_units + fractional;
    return 0;
}

int mxd_format_amount(mxd_amount_t amount, char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) {
        return -1;
    }

    uint64_t whole = amount / MXD_AMOUNT_MULTIPLIER;
    uint64_t fractional = amount % MXD_AMOUNT_MULTIPLIER;

    int written = snprintf(buf, buf_len, "%llu.%08llu MXD", 
                          (unsigned long long)whole, 
                          (unsigned long long)fractional);

    if (written < 0 || (size_t)written >= buf_len) {
        return -1;
    }

    return 0;
}

int mxd_format_amount_plain(mxd_amount_t amount, char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) {
        return -1;
    }

    uint64_t whole = amount / MXD_AMOUNT_MULTIPLIER;
    uint64_t fractional = amount % MXD_AMOUNT_MULTIPLIER;

    int written = snprintf(buf, buf_len, "%llu.%08llu", 
                          (unsigned long long)whole, 
                          (unsigned long long)fractional);

    if (written < 0 || (size_t)written >= buf_len) {
        return -1;
    }

    return 0;
}

int mxd_amount_add(mxd_amount_t a, mxd_amount_t b, mxd_amount_t *result) {
    if (!result) {
        return -1;
    }

    if (a > MXD_AMOUNT_MAX - b) {
        MXD_LOG_ERROR("amount", "Addition overflow: %llu + %llu", 
                     (unsigned long long)a, (unsigned long long)b);
        return -1;
    }

    *result = a + b;
    return 0;
}

int mxd_amount_sub(mxd_amount_t a, mxd_amount_t b, mxd_amount_t *result) {
    if (!result) {
        return -1;
    }

    if (a < b) {
        MXD_LOG_ERROR("amount", "Subtraction underflow: %llu - %llu", 
                     (unsigned long long)a, (unsigned long long)b);
        return -1;
    }

    *result = a - b;
    return 0;
}

int mxd_amount_mul(mxd_amount_t amount, uint64_t multiplier, mxd_amount_t *result) {
    if (!result) {
        return -1;
    }

    if (multiplier != 0 && amount > MXD_AMOUNT_MAX / multiplier) {
        MXD_LOG_ERROR("amount", "Multiplication overflow: %llu * %llu", 
                     (unsigned long long)amount, (unsigned long long)multiplier);
        return -1;
    }

    *result = amount * multiplier;
    return 0;
}

int mxd_amount_div(mxd_amount_t amount, uint64_t divisor, mxd_amount_t *result) {
    if (!result) {
        return -1;
    }

    if (divisor == 0) {
        MXD_LOG_ERROR("amount", "Division by zero");
        return -1;
    }

    *result = amount / divisor;
    return 0;
}

int mxd_amount_from_double(double value, mxd_amount_t *amount) {
    if (!amount) {
        return -1;
    }

    if (value < 0.0) {
        MXD_LOG_ERROR("amount", "Negative amount not allowed: %f", value);
        return -1;
    }

    if (value > (double)MXD_AMOUNT_MAX_WHOLE) {
        MXD_LOG_ERROR("amount", "Amount too large: %f", value);
        return -1;
    }

    double base_units = value * (double)MXD_AMOUNT_MULTIPLIER;
    
    base_units += 0.5;
    
    if (base_units > (double)MXD_AMOUNT_MAX) {
        MXD_LOG_ERROR("amount", "Amount overflow after conversion: %f", value);
        return -1;
    }

    *amount = (mxd_amount_t)base_units;
    return 0;
}

double mxd_amount_to_double(mxd_amount_t amount) {
    return (double)amount / (double)MXD_AMOUNT_MULTIPLIER;
}

int mxd_amount_cmp(mxd_amount_t a, mxd_amount_t b) {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

int mxd_amount_is_zero(mxd_amount_t amount) {
    return amount == 0;
}

mxd_amount_t mxd_amount_min(mxd_amount_t a, mxd_amount_t b) {
    return (a < b) ? a : b;
}

mxd_amount_t mxd_amount_max(mxd_amount_t a, mxd_amount_t b) {
    return (a > b) ? a : b;
}
