#include "common.h"

/* -----------------------------
   SHA-256 Helpers
   ----------------------------- */

void sha256_bytes(const unsigned char *data, size_t len, unsigned char out[HASH_LEN]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx) {
        handle_openssl_error("EVP_MD_CTX_new failed");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        handle_openssl_error("EVP_DigestInit_ex failed");
    }

    if (EVP_DigestUpdate(ctx, data, len) != 1) {
        handle_openssl_error("EVP_DigestUpdate failed");
    }

    unsigned int out_len = 0;

    if (EVP_DigestFinal_ex(ctx, out, &out_len) != 1) {
        handle_openssl_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(ctx);
}

void sha256_concat2(const unsigned char *a, size_t a_len,
                    const unsigned char *b, size_t b_len,
                    unsigned char out[HASH_LEN]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx) {
        handle_openssl_error("EVP_MD_CTX_new failed");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        handle_openssl_error("EVP_DigestInit_ex failed");
    }

    if (EVP_DigestUpdate(ctx, a, a_len) != 1) {
        handle_openssl_error("EVP_DigestUpdate failed");
    }

    if (EVP_DigestUpdate(ctx, b, b_len) != 1) {
        handle_openssl_error("EVP_DigestUpdate failed");
    }

    unsigned int out_len = 0;

    if (EVP_DigestFinal_ex(ctx, out, &out_len) != 1) {
        handle_openssl_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(ctx);
}

void hash_password_with_salt(const char *password,
                             const unsigned char salt[SALT_LEN],
                             unsigned char out[HASH_LEN]) {
    sha256_concat2(
        (const unsigned char *)password,
        strlen(password),
        salt,
        SALT_LEN,
        out
    );
}

void hash_receipt(const BIGNUM *ciphertext,
                  long long timestamp,
                  unsigned char out[HASH_LEN]) {
    int c_len = BN_num_bytes(ciphertext);

    unsigned char *c_bytes = (unsigned char *)xmalloc((size_t)c_len);
    BN_bn2bin(ciphertext, c_bytes);

    unsigned char ts_bytes[8];

    for (int i = 0; i < 8; i++) {
        ts_bytes[7 - i] = (unsigned char)((timestamp >> (i * 8)) & 0xff);
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx) {
        handle_openssl_error("EVP_MD_CTX_new failed");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        handle_openssl_error("EVP_DigestInit_ex failed");
    }

    if (EVP_DigestUpdate(ctx, c_bytes, (size_t)c_len) != 1) {
        handle_openssl_error("EVP_DigestUpdate failed");
    }

    if (EVP_DigestUpdate(ctx, ts_bytes, sizeof(ts_bytes)) != 1) {
        handle_openssl_error("EVP_DigestUpdate failed");
    }

    unsigned int out_len = 0;

    if (EVP_DigestFinal_ex(ctx, out, &out_len) != 1) {
        handle_openssl_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(ctx);
    free(c_bytes);
}

/* -----------------------------
   RSA Key Generation / Signing
   ----------------------------- */

EVP_PKEY *generate_rsa_keypair(void) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *pkey = NULL;

    if (!ctx) {
        handle_openssl_error("EVP_PKEY_CTX_new_id failed");
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        handle_openssl_error("EVP_PKEY_keygen_init failed");
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_BITS) <= 0) {
        handle_openssl_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed");
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        handle_openssl_error("EVP_PKEY_keygen failed");
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

void build_ballot_signing_message(const char *user_id,
                                  const BIGNUM *ciphertext,
                                  long long timestamp,
                                  unsigned char **out,
                                  size_t *out_len) {
    char *c_hex = bn_to_hex_dup(ciphertext);

    char ts_buf[32];
    snprintf(ts_buf, sizeof(ts_buf), "%lld", timestamp);

    size_t len = strlen(user_id) + 1 + strlen(c_hex) + 1 + strlen(ts_buf);

    unsigned char *buf = (unsigned char *)xmalloc(len + 1);

    snprintf((char *)buf, len + 1, "%s|%s|%s", user_id, c_hex, ts_buf);

    free(c_hex);

    *out = buf;
    *out_len = len;
}

void rsa_sign_message(EVP_PKEY *key,
                      const unsigned char *msg,
                      size_t msg_len,
                      unsigned char **sig,
                      size_t *sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx) {
        handle_openssl_error("EVP_MD_CTX_new failed");
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key) != 1) {
        handle_openssl_error("EVP_DigestSignInit failed");
    }

    if (EVP_DigestSignUpdate(ctx, msg, msg_len) != 1) {
        handle_openssl_error("EVP_DigestSignUpdate failed");
    }

    if (EVP_DigestSignFinal(ctx, NULL, sig_len) != 1) {
        handle_openssl_error("EVP_DigestSignFinal length failed");
    }

    *sig = (unsigned char *)xmalloc(*sig_len);

    if (EVP_DigestSignFinal(ctx, *sig, sig_len) != 1) {
        handle_openssl_error("EVP_DigestSignFinal failed");
    }

    EVP_MD_CTX_free(ctx);
}

int rsa_verify_message(EVP_PKEY *pubkey,
                       const unsigned char *msg,
                       size_t msg_len,
                       const unsigned char *sig,
                       size_t sig_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (!ctx) {
        handle_openssl_error("EVP_MD_CTX_new failed");
    }

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pubkey) != 1) {
        handle_openssl_error("EVP_DigestVerifyInit failed");
    }

    if (EVP_DigestVerifyUpdate(ctx, msg, msg_len) != 1) {
        handle_openssl_error("EVP_DigestVerifyUpdate failed");
    }

    int ok = EVP_DigestVerifyFinal(ctx, sig, sig_len);

    EVP_MD_CTX_free(ctx);

    return ok == 1;
}