//
// Created by chaos on 2/25/2021.
//

#ifndef RBC_VALIDATOR_CRYPTO_CIPHER_H_
#define RBC_VALIDATOR_CRYPTO_CIPHER_H_

#include <openssl/evp.h>

int evpEncrypt(unsigned char* cipher, EVP_CIPHER_CTX* ctx, const EVP_CIPHER* evp_cipher,
               const unsigned char* key, const unsigned char* msg, size_t msg_size,
               const unsigned char* iv);

#endif  // RBC_VALIDATOR_CRYPTO_CIPHER_H_
