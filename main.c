#include "common.h"

/* -----------------------------
   Main Program
   ----------------------------- */

int main(void) {
    User users[5];
    Ballot ballots[MAX_BALLOTS];
    int ballot_count = 0;

    printf("\n=== Privacy-Preserving Group Decision Protocol ===\n");
    printf("This build uses OpenSSL-backed cryptography instead of classroom stand-ins.\n");

    /* 1. Setup */
    register_user(&users[0], "alice", "pw1");
    register_user(&users[1], "bob",   "pw2");
    register_user(&users[2], "carol", "pw3");
    register_user(&users[3], "dave",  "pw4");
    register_user(&users[4], "erin",  "pw5");

    PaillierKeyPair pk;
    paillier_init(&pk);
    paillier_keygen(&pk);

    char *n_hex = bn_to_hex_dup(pk.n);
    char *g_hex = bn_to_hex_dup(pk.g);

    printf("\n[SETUP] Paillier public key n = %s\n", n_hex);
    printf("[SETUP] Paillier public key g = %s\n", g_hex);

    free(n_hex);
    free(g_hex);

    printf("[SETUP] Threshold scheme is 3-of-5 using Shamir secret sharing.\n");

    BIGNUM *shamir_mod = generate_large_prime_above(pk.lambda);

    Share authority_shares[MAX_AUTHORITIES];
    for (int i = 0; i < MAX_AUTHORITIES; i++) {
        share_init(&authority_shares[i]);
    }

    generate_shares(pk.lambda, shamir_mod, authority_shares);

    printf("\n[SETUP] Generated 5 shares of the Paillier private key component lambda:\n");
    for (int i = 0; i < MAX_AUTHORITIES; i++) {
        char *y_hex = bn_to_hex_dup(authority_shares[i].y);
        printf("  Authority %d gets share (%d, %s)\n",
               i + 1,
               authority_shares[i].x,
               y_hex);
        free(y_hex);
    }

    /* 2. Authentication + Ballot Casting */
    struct {
        int user_index;
        const char *password_attempt;
        int vote;
    } sessions[] = {
        {0, "pw1", 1},
        {1, "pw2", 1},
        {2, "pw3", 0},
        {3, "pw4", 1},
        {4, "pw5", 0}
    };

    int session_count = (int)(sizeof(sessions) / sizeof(sessions[0]));

    for (int i = 0; i < session_count; i++) {
        User *u = &users[sessions[i].user_index];

        printf("\n[AUTH] %s attempting login...\n", u->username);

        if (authenticate_user(u, sessions[i].password_attempt)) {
            printf("[AUTH] %s authenticated successfully.\n", u->username);

            Ballot b = cast_ballot(u, sessions[i].vote, &pk);

            char *c_hex = bn_to_hex_dup(b.ciphertext);
            printf("[CLIENT] %s casts encrypted vote %d -> ciphertext %s\n",
                   u->username,
                   sessions[i].vote,
                   c_hex);
            free(c_hex);

            printf("[CLIENT] %s receipt hash = ", u->username);
            print_hex_bytes(b.receipt_hash, HASH_LEN);
            printf("\n");

            if (validate_ballot(&b, users, 5)) {
                ballots[ballot_count++] = b;
            } else {
                free_ballot(&b);
            }
        } else {
            printf("[AUTH] %s failed authentication.\n", u->username);
        }
    }

    /* 3. Public accepted ciphertext list */
    print_public_bulletin_board(ballots, ballot_count);

    /* 4. Homomorphic tally */
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        handle_openssl_error("BN_CTX_new failed");
    }

    BIGNUM *encrypted_tally = BN_new();
    if (!encrypted_tally) {
        handle_openssl_error("BN_new failed");
    }

    BN_one(encrypted_tally);

    for (int i = 0; i < ballot_count; i++) {
        if (ballots[i].accepted) {
            BIGNUM *tmp = paillier_homomorphic_add(
                encrypted_tally,
                ballots[i].ciphertext,
                pk.n2
            );

            BN_free(encrypted_tally);
            encrypted_tally = tmp;
        }
    }

    char *enc_tally_hex = bn_to_hex_dup(encrypted_tally);
    printf("\n[TALLY] Combined encrypted tally = %s\n", enc_tally_hex);
    free(enc_tally_hex);

    printf("[TALLY] Server cannot decrypt alone; threshold authorities are required.\n");

    /* 5. Threshold decryption using any 3 shares */
    Share subset[THRESHOLD];
    for (int i = 0; i < THRESHOLD; i++) {
        share_init(&subset[i]);
    }

    subset[0].x = authority_shares[0].x;
    BN_copy(subset[0].y, authority_shares[0].y);

    subset[1].x = authority_shares[2].x;
    BN_copy(subset[1].y, authority_shares[2].y);

    subset[2].x = authority_shares[4].x;
    BN_copy(subset[2].y, authority_shares[4].y);

    printf("\n[THRESHOLD] Using shares from authorities 1, 3, and 5...\n");

    BIGNUM *reconstructed_lambda = reconstruct_secret(subset, shamir_mod);
    char *lambda_hex = bn_to_hex_dup(reconstructed_lambda);
    printf("[THRESHOLD] Reconstructed lambda = %s\n", lambda_hex);
    free(lambda_hex);

    BIGNUM *final_tally = paillier_decrypt(
        encrypted_tally,
        reconstructed_lambda,
        pk.mu,
        pk.n,
        pk.n2
    );

    char *final_tally_dec = BN_bn2dec(final_tally);
    if (!final_tally_dec) {
        handle_openssl_error("BN_bn2dec failed");
    }

    printf("\n[RESULT] Final decrypted tally = %s yes votes\n", final_tally_dec);
    printf("[RESULT] Since there are %d accepted ballots, no-votes = %d\n",
           ballot_count,
           ballot_count - atoi(final_tally_dec));

    OPENSSL_free(final_tally_dec);

    /* 6. Verification summary */
    printf("\n[VERIFICATION] Each voter can verify that:\n");
    printf("  - their receipt hash appears on the public bulletin board\n");
    printf("  - accepted ballots had valid RSA signatures\n");
    printf("  - duplicate votes were rejected by the server\n");
    printf("  - the final tally was computed from accepted encrypted ballots\n");

    printf("\n=== End of Protocol Run ===\n");

    /* cleanup */
    BN_free(final_tally);
    BN_free(reconstructed_lambda);

    for (int i = 0; i < THRESHOLD; i++) {
        share_free(&subset[i]);
    }

    BN_free(encrypted_tally);
    BN_CTX_free(ctx);

    for (int i = 0; i < ballot_count; i++) {
        free_ballot(&ballots[i]);
    }

    for (int i = 0; i < MAX_AUTHORITIES; i++) {
        share_free(&authority_shares[i]);
    }

    BN_free(shamir_mod);
    paillier_free(&pk);

    for (int i = 0; i < 5; i++) {
        free_user(&users[i]);
    }

    return 0;
}