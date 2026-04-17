#include "common.h"

/* -----------------------------
   Paillier Helpers
   ----------------------------- */

void paillier_init(PaillierKeyPair *kp) {
    kp->p = BN_new();
    kp->q = BN_new();
    kp->n = BN_new();
    kp->n2 = BN_new();
    kp->lambda = BN_new();
    kp->g = BN_new();
    kp->mu = BN_new();

    if (!kp->p || !kp->q || !kp->n || !kp->n2 ||
        !kp->lambda || !kp->g || !kp->mu) {
        handle_openssl_error("BN_new failed in paillier_init");
    }
}

void paillier_free(PaillierKeyPair *kp) {
    BN_free(kp->p);
    BN_free(kp->q);
    BN_free(kp->n);
    BN_free(kp->n2);
    BN_free(kp->lambda);
    BN_free(kp->g);
    BN_free(kp->mu);
}

void bn_lcm(BIGNUM *out, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx) {
    BIGNUM *g = BN_new();
    BIGNUM *tmp = BN_new();

    if (!g || !tmp) {
        handle_openssl_error("BN_new failed in bn_lcm");
    }

    if (!BN_gcd(g, a, b, ctx)) {
        handle_openssl_error("BN_gcd failed");
    }

    if (!BN_div(tmp, NULL, a, g, ctx)) {
        handle_openssl_error("BN_div failed");
    }

    if (!BN_mul(out, tmp, b, ctx)) {
        handle_openssl_error("BN_mul failed");
    }

    BN_free(g);
    BN_free(tmp);
}

void paillier_keygen(PaillierKeyPair *kp) {
    BN_CTX *ctx = BN_CTX_new();

    if (!ctx) {
        handle_openssl_error("BN_CTX_new failed");
    }

    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BIGNUM *tmp = BN_new();
    BIGNUM *L = BN_new();
    BIGNUM *one = BN_new();

    if (!p_minus_1 || !q_minus_1 || !tmp || !L || !one) {
        handle_openssl_error("BN_new failed in paillier_keygen");
    }

    if (!BN_generate_prime_ex(kp->p, KEY_BITS / 2, 1, NULL, NULL, NULL)) {
        handle_openssl_error("BN_generate_prime_ex p failed");
    }

    do {
        if (!BN_generate_prime_ex(kp->q, KEY_BITS / 2, 1, NULL, NULL, NULL)) {
            handle_openssl_error("BN_generate_prime_ex q failed");
        }
    } while (BN_cmp(kp->p, kp->q) == 0);

    if (!BN_mul(kp->n, kp->p, kp->q, ctx)) {
        handle_openssl_error("BN_mul n failed");
    }

    if (!BN_sqr(kp->n2, kp->n, ctx)) {
        handle_openssl_error("BN_sqr n2 failed");
    }

    BN_one(one);

    if (!BN_copy(kp->g, kp->n)) {
        handle_openssl_error("BN_copy g failed");
    }

    if (!BN_add(kp->g, kp->g, one)) {
        handle_openssl_error("BN_add g=n+1 failed");
    }

    if (!BN_copy(p_minus_1, kp->p) ||
        !BN_sub(p_minus_1, p_minus_1, one)) {
        handle_openssl_error("p-1 failed");
    }

    if (!BN_copy(q_minus_1, kp->q) ||
        !BN_sub(q_minus_1, q_minus_1, one)) {
        handle_openssl_error("q-1 failed");
    }

    bn_lcm(kp->lambda, p_minus_1, q_minus_1, ctx);

    if (!BN_mod_exp(tmp, kp->g, kp->lambda, kp->n2, ctx)) {
        handle_openssl_error("BN_mod_exp failed for g^lambda mod n^2");
    }

    if (!BN_sub(tmp, tmp, one)) {
        handle_openssl_error("tmp-1 failed");
    }

    if (!BN_div(L, NULL, tmp, kp->n, ctx)) {
        handle_openssl_error("BN_div L failed");
    }

    BIGNUM *mu = BN_mod_inverse(NULL, L, kp->n, ctx);

    if (!mu) {
        handle_openssl_error("BN_mod_inverse for mu failed");
    }

    if (!BN_copy(kp->mu, mu)) {
        handle_openssl_error("BN_copy mu failed");
    }

    BN_free(mu);
    BN_free(p_minus_1);
    BN_free(q_minus_1);
    BN_free(tmp);
    BN_free(L);
    BN_free(one);
    BN_CTX_free(ctx);
}

BIGNUM *paillier_encrypt_int(int m, const PaillierKeyPair *kp) {
    BN_CTX *ctx = BN_CTX_new();

    if (!ctx) {
        handle_openssl_error("BN_CTX_new failed");
    }

    BIGNUM *message = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *gm = BN_new();
    BIGNUM *rn = BN_new();
    BIGNUM *c = BN_new();
    BIGNUM *gcd = BN_new();
    BIGNUM *one = BN_new();

    if (!message || !r || !gm || !rn || !c || !gcd || !one) {
        handle_openssl_error("BN_new failed in paillier_encrypt_int");
    }

    BN_one(one);

    if (!BN_set_word(message, (unsigned long)m)) {
        handle_openssl_error("BN_set_word message failed");
    }

    do {
        if (!BN_rand_range(r, kp->n)) {
            handle_openssl_error("BN_rand_range failed");
        }

        if (BN_is_zero(r)) {
            continue;
        }

        if (!BN_gcd(gcd, r, kp->n, ctx)) {
            handle_openssl_error("BN_gcd failed");
        }

    } while (BN_cmp(gcd, one) != 0);

    if (!BN_mod_exp(gm, kp->g, message, kp->n2, ctx)) {
        handle_openssl_error("BN_mod_exp gm failed");
    }

    if (!BN_mod_exp(rn, r, kp->n, kp->n2, ctx)) {
        handle_openssl_error("BN_mod_exp rn failed");
    }

    if (!BN_mod_mul(c, gm, rn, kp->n2, ctx)) {
        handle_openssl_error("BN_mod_mul c failed");
    }

    BN_free(message);
    BN_free(r);
    BN_free(gm);
    BN_free(rn);
    BN_free(gcd);
    BN_free(one);
    BN_CTX_free(ctx);

    return c;
}

BIGNUM *paillier_decrypt(const BIGNUM *c,
                         const BIGNUM *lambda,
                         const BIGNUM *mu,
                         const BIGNUM *n,
                         const BIGNUM *n2) {
    BN_CTX *ctx = BN_CTX_new();

    if (!ctx) {
        handle_openssl_error("BN_CTX_new failed");
    }

    BIGNUM *u = BN_new();
    BIGNUM *L = BN_new();
    BIGNUM *m = BN_new();
    BIGNUM *one = BN_new();

    if (!u || !L || !m || !one) {
        handle_openssl_error("BN_new failed in paillier_decrypt");
    }

    BN_one(one);

    if (!BN_mod_exp(u, c, lambda, n2, ctx)) {
        handle_openssl_error("BN_mod_exp decrypt failed");
    }

    if (!BN_sub(u, u, one)) {
        handle_openssl_error("u-1 failed");
    }

    if (!BN_div(L, NULL, u, n, ctx)) {
        handle_openssl_error("BN_div L failed");
    }

    if (!BN_mod_mul(m, L, mu, n, ctx)) {
        handle_openssl_error("BN_mod_mul m failed");
    }

    BN_free(u);
    BN_free(L);
    BN_free(one);
    BN_CTX_free(ctx);

    return m;
}

BIGNUM *paillier_homomorphic_add(const BIGNUM *c1,
                                 const BIGNUM *c2,
                                 const BIGNUM *n2) {
    BN_CTX *ctx = BN_CTX_new();

    if (!ctx) {
        handle_openssl_error("BN_CTX_new failed");
    }

    BIGNUM *out = BN_new();

    if (!out) {
        handle_openssl_error("BN_new failed in paillier_homomorphic_add");
    }

    if (!BN_mod_mul(out, c1, c2, n2, ctx)) {
        handle_openssl_error("BN_mod_mul homomorphic add failed");
    }

    BN_CTX_free(ctx);

    return out;
}