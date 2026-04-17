#include "common.h"

/* -----------------------------
   User / Ballot Helpers
   ----------------------------- */

void register_user(User *u, const char *username, const char *password) {
    memset(u, 0, sizeof(User));

    strncpy(u->username, username, sizeof(u->username) - 1);
    strncpy(u->password, password, sizeof(u->password) - 1);

    if (RAND_bytes(u->salt, SALT_LEN) != 1) {
        handle_openssl_error("RAND_bytes failed for salt");
    }

    hash_password_with_salt(password, u->salt, u->stored_password_hash);

    u->rsa_keypair = generate_rsa_keypair();
    u->has_voted = 0;
}

void free_user(User *u) {
    EVP_PKEY_free(u->rsa_keypair);
}

int authenticate_user(User *u, const char *password_attempt) {
    unsigned char computed[HASH_LEN];

    hash_password_with_salt(password_attempt, u->salt, computed);

    return CRYPTO_memcmp(computed, u->stored_password_hash, HASH_LEN) == 0;
}

Ballot cast_ballot(User *u, int vote, const PaillierKeyPair *kp) {
    Ballot b;
    memset(&b, 0, sizeof(Ballot));

    strncpy(b.user_id, u->username, sizeof(b.user_id) - 1);
    b.timestamp = (long long)time(NULL);

    b.ciphertext = paillier_encrypt_int(vote, kp);
    hash_receipt(b.ciphertext, b.timestamp, b.receipt_hash);

    unsigned char *msg = NULL;
    size_t msg_len = 0;

    build_ballot_signing_message(
        b.user_id,
        b.ciphertext,
        b.timestamp,
        &msg,
        &msg_len
    );

    rsa_sign_message(
        u->rsa_keypair,
        msg,
        msg_len,
        &b.signature,
        &b.signature_len
    );

    free(msg);

    b.accepted = 0;
    return b;
}

void free_ballot(Ballot *b) {
    BN_free(b->ciphertext);
    free(b->signature);
}

int validate_ballot(Ballot *b, User users[], int user_count) {
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].username, b->user_id) == 0) {
            if (users[i].has_voted) {
                printf("[SERVER] Rejecting ballot from %s: duplicate vote detected.\n", b->user_id);
                return 0;
            }

            unsigned char *msg = NULL;
            size_t msg_len = 0;

            build_ballot_signing_message(
                b->user_id,
                b->ciphertext,
                b->timestamp,
                &msg,
                &msg_len
            );

            int sig_ok = rsa_verify_message(
                users[i].rsa_keypair,
                msg,
                msg_len,
                b->signature,
                b->signature_len
            );

            free(msg);

            if (!sig_ok) {
                printf("[SERVER] Rejecting ballot from %s: invalid RSA signature.\n", b->user_id);
                return 0;
            }

            unsigned char expected_receipt[HASH_LEN];
            hash_receipt(b->ciphertext, b->timestamp, expected_receipt);

            if (CRYPTO_memcmp(expected_receipt, b->receipt_hash, HASH_LEN) != 0) {
                printf("[SERVER] Rejecting ballot from %s: receipt hash mismatch.\n", b->user_id);
                return 0;
            }

            users[i].has_voted = 1;
            b->accepted = 1;

            printf("[SERVER] Accepted ballot from %s.\n", b->user_id);
            return 1;
        }
    }

    printf("[SERVER] Rejecting ballot: unknown user %s.\n", b->user_id);
    return 0;
}

void print_public_bulletin_board(Ballot ballots[], int ballot_count) {
    printf("\n================ PUBLIC ACCEPTED CIPHERTEXT LIST ================\n");

    for (int i = 0; i < ballot_count; i++) {
        if (ballots[i].accepted) {
            char *c_hex = bn_to_hex_dup(ballots[i].ciphertext);

            printf("Ballot %d | User: %-8s | Ciphertext: %s\n",
                   i + 1,
                   ballots[i].user_id,
                   c_hex);

            printf("          | Timestamp: %-12lld | Receipt Hash: ",
                   ballots[i].timestamp);

            print_hex_bytes(ballots[i].receipt_hash, HASH_LEN);
            printf("\n");

            free(c_hex);
        }
    }

    printf("===============================================================\n");
}