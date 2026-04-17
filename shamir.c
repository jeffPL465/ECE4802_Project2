#include "common.h"

/* -----------------------------
   Shamir Secret Sharing (3-of-5)
   ----------------------------- */

void share_init(Share *s) {
    s->y = BN_new();

    if (!s->y) {
        handle_openssl_error("BN_new failed for share");
    }
}

void share_free(Share *s) {
    BN_free(s->y);
}

BIGNUM *generate_large_prime_above(const BIGNUM *min_value) {
    BIGNUM *prime = BN_dup(min_value);

    if (!prime) {
        handle_openssl_error("BN_dup failed for prime generation");
    }

    if (!BN_set_bit(prime, SHARE_PRIME_BITS - 1)) {
        handle_openssl_error("BN_set_bit failed");
    }

    if (BN_cmp(prime, min_value) <= 0) {
        if (!BN_copy(prime, min_value)) {
            handle_openssl_error("BN_copy failed");
        }

        if (!BN_add_word(prime, 1)) {
            handle_openssl_error("BN_add_word failed");
        }
    }

    if (!BN_generate_prime_ex(prime, SHARE_PRIME_BITS, 1, prime, NULL, NULL)) {
        handle_openssl_error("BN_generate_prime_ex for share field failed");
    }

    return prime;
}

void generate_shares(const BIGNUM *secret,
                     const BIGNUM *mod,
                     Share shares[MAX_AUTHORITIES]) {
    BN_CTX *ctx = BN_CTX_new();

    if (!ctx) {
        handle_openssl_error("BN_CTX_new failed");
    }

    BIGNUM *a1 = BN_new();
    BIGNUM *a2 = BN_new();
    BIGNUM *x_bn = BN_new();
    BIGNUM *term1 = BN_new();
    BIGNUM *term2 = BN_new();
    BIGNUM *x2 = BN_new();

    if (!a1 || !a2 || !x_bn || !term1 || !term2 || !x2) {
        handle_openssl_error("BN_new failed in generate_shares");
    }

    if (!BN_rand_range(a1, mod)) {
        handle_openssl_error("BN_rand_range a1 failed");
    }

    if (!BN_rand_range(a2, mod)) {
        handle_openssl_error("BN_rand_range a2 failed");
    }

    for (int i = 0; i < MAX_AUTHORITIES; i++) {
        shares[i].x = i + 1;

        if (!BN_set_word(x_bn, (unsigned long)shares[i].x)) {
            handle_openssl_error("BN_set_word x failed");
        }

        if (!BN_mod_mul(term1, a1, x_bn, mod, ctx)) {
            handle_openssl_error("BN_mod_mul term1 failed");
        }

        if (!BN_mod_mul(x2, x_bn, x_bn, mod, ctx)) {
            handle_openssl_error("BN_mod_mul x2 failed");
        }

        if (!BN_mod_mul(term2, a2, x2, mod, ctx)) {
            handle_openssl_error("BN_mod_mul term2 failed");
        }

        if (!BN_mod_add(shares[i].y, secret, term1, mod, ctx)) {
            handle_openssl_error("BN_mod_add share secret+term1 failed");
        }

        if (!BN_mod_add(shares[i].y, shares[i].y, term2, mod, ctx)) {
            handle_openssl_error("BN_mod_add share +term2 failed");
        }
    }

    BN_free(a1);
    BN_free(a2);
    BN_free(x_bn);
    BN_free(term1);
    BN_free(term2);
    BN_free(x2);
    BN_CTX_free(ctx);
}

BIGNUM *reconstruct_secret(Share subset[THRESHOLD], const BIGNUM *mod) {
    BN_CTX *ctx = BN_CTX_new();

    if (!ctx) {
        handle_openssl_error("BN_CTX_new failed");
    }

    BIGNUM *secret = BN_new();
    BIGNUM *numerator = BN_new();
    BIGNUM *denominator = BN_new();
    BIGNUM *xj = BN_new();
    BIGNUM *xm = BN_new();
    BIGNUM *neg_xm = BN_new();
    BIGNUM *diff = BN_new();
    BIGNUM *inv_den = NULL;
    BIGNUM *lj = BN_new();
    BIGNUM *term = BN_new();
    BIGNUM *tmp = BN_new();
    BIGNUM *one = BN_new();

    if (!secret || !numerator || !denominator || !xj || !xm ||
        !neg_xm || !diff || !lj || !term || !tmp || !one) {
        handle_openssl_error("BN_new failed in reconstruct_secret");
    }

    BN_zero(secret);
    BN_one(one);

    for (int j = 0; j < THRESHOLD; j++) {
        if (!BN_copy(numerator, one)) {
            handle_openssl_error("BN_copy numerator failed");
        }

        if (!BN_copy(denominator, one)) {
            handle_openssl_error("BN_copy denominator failed");
        }

        if (!BN_set_word(xj, (unsigned long)subset[j].x)) {
            handle_openssl_error("BN_set_word xj failed");
        }

        for (int m = 0; m < THRESHOLD; m++) {
            if (m == j) {
                continue;
            }

            if (!BN_set_word(xm, (unsigned long)subset[m].x)) {
                handle_openssl_error("BN_set_word xm failed");
            }

            if (!BN_mod_sub(neg_xm, mod, xm, mod, ctx)) {
                handle_openssl_error("BN_mod_sub neg_xm failed");
            }

            if (!BN_mod_mul(numerator, numerator, neg_xm, mod, ctx)) {
                handle_openssl_error("BN_mod_mul numerator failed");
            }

            if (!BN_mod_sub(diff, xj, xm, mod, ctx)) {
                handle_openssl_error("BN_mod_sub diff failed");
            }

            if (!BN_mod_mul(denominator, denominator, diff, mod, ctx)) {
                handle_openssl_error("BN_mod_mul denominator failed");
            }
        }

        inv_den = BN_mod_inverse(NULL, denominator, mod, ctx);

        if (!inv_den) {
            handle_openssl_error("BN_mod_inverse denominator failed");
        }

        if (!BN_mod_mul(lj, numerator, inv_den, mod, ctx)) {
            handle_openssl_error("BN_mod_mul lj failed");
        }

        if (!BN_mod_mul(term, subset[j].y, lj, mod, ctx)) {
            handle_openssl_error("BN_mod_mul term failed");
        }

        if (!BN_mod_add(tmp, secret, term, mod, ctx)) {
            handle_openssl_error("BN_mod_add secret failed");
        }

        if (!BN_copy(secret, tmp)) {
            handle_openssl_error("BN_copy secret failed");
        }

        BN_free(inv_den);
        inv_den = NULL;
    }

    BN_free(numerator);
    BN_free(denominator);
    BN_free(xj);
    BN_free(xm);
    BN_free(neg_xm);
    BN_free(diff);
    BN_free(lj);
    BN_free(term);
    BN_free(tmp);
    BN_free(one);
    BN_CTX_free(ctx);

    return secret;
}