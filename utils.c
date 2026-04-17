#include "common.h"

/* -----------------------------
   OpenSSL / General Utilities
   ----------------------------- */

void handle_openssl_error(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

void *xmalloc(size_t n) {
    void *p = malloc(n);

    if (!p) {
        fprintf(stderr, "Out of memory\n");
        exit(EXIT_FAILURE);
    }

    return p;
}

char *bn_to_hex_dup(const BIGNUM *bn) {
    char *tmp = BN_bn2hex(bn);

    if (!tmp) {
        handle_openssl_error("BN_bn2hex failed");
    }

    char *out = strdup(tmp);
    OPENSSL_free(tmp);

    if (!out) {
        fprintf(stderr, "Out of memory\n");
        exit(EXIT_FAILURE);
    }

    return out;
}

void print_hex_bytes(const unsigned char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

int bn_to_padded_bytes(const BIGNUM *bn, unsigned char *out, int out_len) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    return BN_bn2binpad(bn, out, out_len);
#else
    int bn_len = BN_num_bytes(bn);

    if (bn_len > out_len) {
        return -1;
    }

    memset(out, 0, out_len - bn_len);
    BN_bn2bin(bn, out + (out_len - bn_len));

    return out_len;
#endif
}