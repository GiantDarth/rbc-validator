//
// Created by chaos on 2/28/2021.
//

#ifndef RBC_VALIDATOR_HASH_H
#define RBC_VALIDATOR_HASH_H

#include <openssl/evp.h>

int evp_hash(unsigned char *digest, EVP_MD_CTX *ctx, const EVP_MD *md,
             const unsigned char *msg, size_t msg_size,
             const unsigned char *salt, size_t salt_size);
int md5_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
             const unsigned char *salt, size_t salt_size);
int sha1_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
              const unsigned char *salt, size_t salt_size);
int sha224_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                const unsigned char *salt, size_t salt_size);
int sha256_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                const unsigned char *salt, size_t salt_size);
int sha384_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                const unsigned char *salt, size_t salt_size);
int sha512_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                const unsigned char *salt, size_t salt_size);
int sha3_224_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                  const unsigned char *salt, size_t salt_size);
int sha3_256_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                  const unsigned char *salt, size_t salt_size);
int sha3_384_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                  const unsigned char *salt, size_t salt_size);
int sha3_512_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                  const unsigned char *salt, size_t salt_size);
int kang12_hash(unsigned char *digest, size_t digest_size, const unsigned char *msg, size_t msg_size,
                const unsigned char *salt, size_t salt_size);

#endif //RBC_VALIDATOR_HASH_H
