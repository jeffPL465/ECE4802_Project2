CC = gcc
CFLAGS = -Wall -Wextra -O2

# macOS Homebrew OpenSSL path
OPENSSL_CFLAGS = -I/opt/homebrew/opt/openssl@3/include
OPENSSL_LDFLAGS = -L/opt/homebrew/opt/openssl@3/lib -lcrypto

SRC = main.c utils.c hash_rsa.c paillier.c shamir.c protocol.c
OUT = protocol_demo

all:
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) $(OPENSSL_CFLAGS) $(OPENSSL_LDFLAGS)

linux:
	$(CC) $(CFLAGS) $(SRC) -o $(OUT) -lcrypto

clean:
	rm -f $(OUT)