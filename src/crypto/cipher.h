//
// Created by chaos on 2/25/2021.
//

#ifndef RBC_VALIDATOR_CIPHER_H
#define RBC_VALIDATOR_CIPHER_H

#include <openssl/evp.h>

int evp_encrypt(unsigned char *cipher, EVP_CIPHER_CTX *ctx, const EVP_CIPHER *evp_cipher,
                const unsigned char *key, const unsigned char *msg, size_t msg_size,
                const unsigned char *iv);

#endif //RBC_VALIDATOR_CIPHER_H
