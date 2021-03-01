//
// Created by chaos on 2/28/2021.
//

#ifndef RBC_VALIDATOR_HASH_H
#define RBC_VALIDATOR_HASH_H

#include <openssl/evp.h>

int evp_hash(unsigned char *digest, EVP_MD_CTX *ctx, const EVP_MD *md,
             const unsigned char *msg, size_t msg_size);
int evp_salt_hash(unsigned char *digest, EVP_MD_CTX *ctx, const EVP_MD *md,
                  const unsigned char *msg, size_t msg_size,
                  const unsigned char *salt, size_t salt_size);

#endif //RBC_VALIDATOR_HASH_H
