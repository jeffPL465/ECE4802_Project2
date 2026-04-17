# Privacy-Preserving Group Decision Protocol

This project is a C implementation of a privacy-preserving voting protocol using real cryptographic primitives through OpenSSL. It keeps the same protocol flow as the original single-file demo, but replaces the simplified stand-ins with actual hashing, RSA signing, Paillier encryption, and Shamir secret sharing logic.

## How the code works

The protocol runs in these phases:

1. **Setup**
   - Users are registered with usernames and salted SHA-256 password hashes.
   - Each user generates an RSA keypair for ballot signing.
   - A Paillier keypair is generated for vote encryption and homomorphic tallying.
   - The Paillier private value is split using 3-of-5 Shamir secret sharing.

2. **Authentication**
   - A user logs in by submitting a password.
   - The password is hashed with the stored salt and compared to the saved hash.

3. **Ballot Casting**
   - A vote is encrypted with the Paillier public key.
   - A receipt hash is computed from the ciphertext and timestamp.
   - The ballot is signed with the user's RSA private key.

4. **Validation**
   - The server verifies the RSA signature.
   - The server checks the receipt hash.
   - Duplicate votes are rejected.

5. **Tallying**
   - Accepted ciphertexts are multiplied together to produce an encrypted tally.

6. **Threshold Reconstruction**
   - Any 3 of 5 Shamir shares reconstruct the Paillier private value.
   - The encrypted tally is decrypted to reveal the final yes-vote count.

7. **Verification**
   - The bulletin board shows accepted ciphertexts and receipt hashes.
   - Voters can verify their ballot was included.
   - The protocol flow demonstrates integrity, privacy, and threshold trust.

## Files

- `common.h` - shared constants, structs, and function declarations
- `utils.c` - general helper and formatting functions
- `hash_rsa.c` - SHA-256 hashing and RSA key/signature functions
- `paillier.c` - Paillier key generation, encryption, decryption, and homomorphic addition
- `shamir.c` - Shamir secret sharing and reconstruction
- `protocol.c` - user registration, authentication, ballot casting, ballot validation, bulletin board
- `main.c` - top-level protocol execution flow

## Dependencies

### macOS
- Xcode Command Line Tools
- Homebrew
- OpenSSL 3

Install with:
```bash
xcode-select --install
brew install openssl@3