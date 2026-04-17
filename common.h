#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

/* -----------------------------
   Global Constants
   ----------------------------- */

#define MAX_USERS 10
#define MAX_BALLOTS 10
#define MAX_AUTHORITIES 5
#define THRESHOLD 3
#define SALT_LEN 16
#define HASH_LEN 32
#define KEY_BITS 2048
#define SHARE_PRIME_BITS 4096

/* -----------------------------
   Shared Data Structures
   ----------------------------- */

typedef struct {
    char username[32];
    char password[64];
    unsigned char salt[SALT_LEN];
    unsigned char stored_password_hash[HASH_LEN];

    /* RSA keypair stored with OpenSSL EVP interface */
    EVP_PKEY *rsa_keypair;

    int has_voted;
} User;

typedef struct {
    char user_id[32];
    BIGNUM *ciphertext;
    unsigned char *signature;
    size_t signature_len;
    long long timestamp;
    unsigned char receipt_hash[HASH_LEN];
    int accepted;
} Ballot;

typedef struct {
    int x;
    BIGNUM *y;
} Share;

typedef struct {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *n;
    BIGNUM *n2;
    BIGNUM *lambda;
    BIGNUM *g;
    BIGNUM *mu;
} PaillierKeyPair;

/* -----------------------------
   Utility Function Prototypes
   ----------------------------- */

void handle_openssl_error(const char *msg);
void *xmalloc(size_t n);
char *bn_to_hex_dup(const BIGNUM *bn);
void print_hex_bytes(const unsigned char *buf, size_t len);
int bn_to_padded_bytes(const BIGNUM *bn, unsigned char *out, int out_len);

/* -----------------------------
   Hash / RSA Function Prototypes
   ----------------------------- */

void sha256_bytes(const unsigned char *data, size_t len, unsigned char out[HASH_LEN]);

void sha256_concat2(
    const unsigned char *a, size_t a_len,
    const unsigned char *b, size_t b_len,
    unsigned char out[HASH_LEN]);

void hash_password_with_salt(
    const char *password,
    const unsigned char salt[SALT_LEN],
    unsigned char out[HASH_LEN]);

void hash_receipt(const BIGNUM *ciphertext, long long timestamp, unsigned char out[HASH_LEN]);

EVP_PKEY *generate_rsa_keypair(void);

void build_ballot_signing_message(
    const char *user_id,
    const BIGNUM *ciphertext,
    long long timestamp,
    unsigned char **out,
    size_t *out_len);

void rsa_sign_message(
    EVP_PKEY *key,
    const unsigned char *msg,
    size_t msg_len,
    unsigned char **sig,
    size_t *sig_len);

int rsa_verify_message(
    EVP_PKEY *pubkey,
    const unsigned char *msg,
    size_t msg_len,
    const unsigned char *sig,
    size_t sig_len);

    /* -----------------------------
   Paillier Function Prototypes
   ----------------------------- */

void paillier_init(PaillierKeyPair *kp);
void paillier_free(PaillierKeyPair *kp);
void bn_lcm(BIGNUM *out, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
void paillier_keygen(PaillierKeyPair *kp);

BIGNUM *paillier_encrypt_int(int m, const PaillierKeyPair *kp);

BIGNUM *paillier_decrypt(
    const BIGNUM *c,
    const BIGNUM *lambda,
    const BIGNUM *mu,
    const BIGNUM *n,
    const BIGNUM *n2);

BIGNUM *paillier_homomorphic_add(
    const BIGNUM *c1,
    const BIGNUM *c2,
    const BIGNUM *n2);

/* -----------------------------
   Shamir Function Prototypes
   ----------------------------- */

void share_init(Share *s);
void share_free(Share *s);
BIGNUM *generate_large_prime_above(const BIGNUM *min_value);
void generate_shares(const BIGNUM *secret, const BIGNUM *mod, Share shares[MAX_AUTHORITIES]);
BIGNUM *reconstruct_secret(Share subset[THRESHOLD], const BIGNUM *mod);

/* -----------------------------
   Protocol Function Prototypes
   ----------------------------- */

void register_user(User *u, const char *username, const char *password);
void free_user(User *u);
int authenticate_user(User *u, const char *password_attempt);
Ballot cast_ballot(User *u, int vote, const PaillierKeyPair *kp);
void free_ballot(Ballot *b);
int validate_ballot(Ballot *b, User users[], int user_count);
void print_public_bulletin_board(Ballot ballots[], int ballot_count);

#endif /* COMMON_H */