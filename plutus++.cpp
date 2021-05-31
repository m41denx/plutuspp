#include <iostream>
#include <sodium.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include "utils/base58.h"

void genprivkey(char *xrand);
void genpublickey(char *privKey);
void base58(char* hexAddr);


int main() {
    char privkey[32];
    genprivkey(privkey);
    std::cout << privkey;
}


void genprivkey(char *xrand) {
    randombytes_buf(xrand, 32);
}

void genpublickey(char *privKey) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);

    if (!key) {
        std::cerr << "Error creating curve key" << '\n';
    }

    if (!EC_KEY_generate_key(key)) {
        std::cerr << "Error generating curve key" << '\n';
        EC_KEY_free(key);
    }

    BIGNUM const *prv = EC_KEY_get0_private_key(key);
    if (!prv) {
        std::cerr << "Error getting private key" << '\n';
        EC_KEY_free(key);
    }

    std::cout << "Private key: " << prv << '\n';

    EC_POINT const *pub = EC_KEY_get0_public_key(key);
    if (!pub) {
        std::cerr << "Error getting public key" << '\n';
        EC_KEY_free(key);
    }

    std::cout << "Public key: " << pub << '\n';

// Use keys here ...

    EC_KEY_free(key);
}