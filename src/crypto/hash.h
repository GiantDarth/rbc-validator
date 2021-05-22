//
// Created by chaos on 2/28/2021.
//

#ifndef RBC_VALIDATOR_HASH_H
#define RBC_VALIDATOR_HASH_H

#include <openssl/evp.h>

#define NID_kang12 -1

/// A generic function that allows for any combination of hash functions through OpenSSL's EVP system.
/// \param digest The output digest. It must be pre-allocated with at least the correct digest size.
/// \param digest_size Either NULL for any non-XOF, or the wanted digest size when using EVP_shake128
/// or EVP_shake256. Using a non-NULL size on a non-XOF is undefined behavior.
/// \param ctx A context the perform the digest operations in. If NULL (aka. not pre-allocated), then
/// it will allocate and destroy a temporary context at the cost of performance.
/// \param md Which hash function to use.
/// \param msg The message to hash, must have at least msg_size bytes allocated.
/// \param msg_size How many bytes are allocated for msg.
/// \param salt An additional, optional salt that will perform a secondary update after msg.
/// \param salt_size How big the salt is. If salt is NULL, then this value is ignored.
/// \return Returns a 0 on success and a 1 on failure.
int evp_hash(unsigned char *digest, const size_t *digest_size, EVP_MD_CTX *ctx,
             const EVP_MD *md, const unsigned char *msg, size_t msg_size,
             const unsigned char *salt, size_t salt_size);
/// Perform MD5 using OpenSSL's faster low level functions.
/// \param digest The output digest. It must be pre-allocated with at least 16 bytes.
/// \param msg The message to hash, must have at least msg_size bytes allocated.
/// \param msg_size How many bytes are allocated for msg.
/// \param salt An additional, optional salt that will perform a secondary update after msg.
/// \param salt_size How big the salt is. If salt is NULL, then this value is ignored.
/// \return Returns a 0 on success and a 1 on failure.
int md5_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
             const unsigned char *salt, size_t salt_size);
/// Perform SHA1 using OpenSSL's faster low level functions.
/// \param digest The output digest. It must be pre-allocated with at least 20 bytes.
/// \param msg The message to hash, must have at least msg_size bytes allocated.
/// \param msg_size How many bytes are allocated for msg.
/// \param salt An additional, optional salt that will perform a secondary update after msg.
/// \param salt_size How big the salt is. If salt is NULL, then this value is ignored.
/// \return Returns a 0 on success and a 1 on failure.
int sha1_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
              const unsigned char *salt, size_t salt_size);
/// Perform SHA224 using OpenSSL's faster low level functions.
/// \param digest The output digest. It must be pre-allocated with at least 24 bytes.
/// \param msg The message to hash, must have at least msg_size bytes allocated.
/// \param msg_size How many bytes are allocated for msg.
/// \param salt An additional, optional salt that will perform a secondary update after msg.
/// \param salt_size How big the salt is. If salt is NULL, then this value is ignored.
/// \return Returns a 0 on success and a 1 on failure.
int sha224_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                const unsigned char *salt, size_t salt_size);
/// Perform SHA256 using OpenSSL's faster low level functions.
/// \param digest The output digest. It must be pre-allocated with at least 32 bytes.
/// \param msg The message to hash, must have at least msg_size bytes allocated.
/// \param msg_size How many bytes are allocated for msg.
/// \param salt An additional, optional salt that will perform a secondary update after msg.
/// \param salt_size How big the salt is. If salt is NULL, then this value is ignored.
/// \return Returns a 0 on success and a 1 on failure.
int sha256_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                const unsigned char *salt, size_t salt_size);
/// Perform SHA384 using OpenSSL's faster low level functions.
/// \param digest The output digest. It must be pre-allocated with at least 48 bytes.
/// \param msg The message to hash, must have at least msg_size bytes allocated.
/// \param msg_size How many bytes are allocated for msg.
/// \param salt An additional, optional salt that will perform a secondary update after msg.
/// \param salt_size How big the salt is. If salt is NULL, then this value is ignored.
/// \return Returns a 0 on success and a 1 on failure.
int sha384_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                const unsigned char *salt, size_t salt_size);
/// Perform SHA512 using OpenSSL's faster low level functions.
/// \param digest The output digest. It must be pre-allocated with at least 64 bytes.
/// \param msg The message to hash, must have at least msg_size bytes allocated.
/// \param msg_size How many bytes are allocated for msg.
/// \param salt An additional, optional salt that will perform a secondary update after msg.
/// \param salt_size How big the salt is. If salt is NULL, then this value is ignored.
/// \return Returns a 0 on success and a 1 on failure.
int sha512_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                const unsigned char *salt, size_t salt_size);
/// Perform SHA3-224 using XKCP's (potentially) faster low level functions.
/// \param digest The output digest. It must be pre-allocated with at least 24 bytes.
/// \param msg The message to hash, must have at least msg_size bytes allocated.
/// \param msg_size How many bytes are allocated for msg.
/// \param salt An additional, optional salt that will perform a secondary update after msg.
/// \param salt_size How big the salt is. If salt is NULL, then this value is ignored.
/// \return Returns a 0 on success and a 1 on failure.
int sha3_224_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                  const unsigned char *salt, size_t salt_size);
/// Perform SHA3-256 using XKCP's (potentially) faster low level functions.
/// \param digest The output digest. It must be pre-allocated with at least 32 bytes.
/// \param msg The message to hash, must have at least msg_size bytes allocated.
/// \param msg_size How many bytes are allocated for msg.
/// \param salt An additional, optional salt that will perform a secondary update after msg.
/// \param salt_size How big the salt is. If salt is NULL, then this value is ignored.
/// \return Returns a 0 on success and a 1 on failure.
int sha3_256_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                  const unsigned char *salt, size_t salt_size);
/// Perform SHA3-384 using XKCP's (potentially) faster low level functions.
/// \param digest The output digest. It must be pre-allocated with at least 48 bytes.
/// \param msg The message to hash, must have at least msg_size bytes allocated.
/// \param msg_size How many bytes are allocated for msg.
/// \param salt An additional, optional salt that will perform a secondary update after msg.
/// \param salt_size How big the salt is. If salt is NULL, then this value is ignored.
/// \return Returns a 0 on success and a 1 on failure.
int sha3_384_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                  const unsigned char *salt, size_t salt_size);
/// Perform SHA3-512 using XKCP's (potentially) faster low level functions.
/// \param digest The output digest. It must be pre-allocated with at least 64 bytes.
/// \param msg The message to hash, must have at least msg_size bytes allocated.
/// \param msg_size How many bytes are allocated for msg.
/// \param salt An additional, optional salt that will perform a secondary update after msg.
/// \param salt_size How big the salt is. If salt is NULL, then this value is ignored.
/// \return Returns a 0 on success and a 1 on failure.
int sha3_512_hash(unsigned char *digest, const unsigned char *msg, size_t msg_size,
                  const unsigned char *salt, size_t salt_size);
/// Perform SHAKE128 using XKCP's (potentially) faster low level functions.
/// \param digest The output digest. It must be pre-allocated with at least digest_size bytes.
/// \param digest_size How many bytes you want to fill digest with. digest must be pre-allocated
/// with at least this many bytes.
/// \param msg The message to hash, must have at least msg_size bytes allocated.
/// \param msg_size How many bytes are allocated for msg.
/// \param salt An additional, optional salt that will perform a secondary update after msg.
/// \param salt_size How big the salt is. If salt is NULL, then this value is ignored.
/// \return Returns a 0 on success and a 1 on failure.
int shake128_hash(unsigned char *digest, size_t digest_size,
                  const unsigned char *msg, size_t msg_size,
                  const unsigned char *salt, size_t salt_size);
/// Perform SHAKE256 using XKCP's (potentially) faster low level functions.
/// \param digest The output digest. It must be pre-allocated with at least digest_size bytes.
/// \param digest_size How many bytes you want to fill digest with. digest must be pre-allocated
/// with at least this many bytes.
/// \param msg The message to hash, must have at least msg_size bytes allocated.
/// \param msg_size How many bytes are allocated for msg.
/// \param salt An additional, optional salt that will perform a secondary update after msg.
/// \param salt_size How big the salt is. If salt is NULL, then this value is ignored.
/// \return Returns a 0 on success and a 1 on failure.
int shake256_hash(unsigned char *digest, size_t digest_size,
                  const unsigned char *msg, size_t msg_size,
                  const unsigned char *salt, size_t salt_size);
/// Perform KangarooTwelve using XKCP.
/// \param digest The output digest. It must be pre-allocated with at least digest_size bytes.
/// \param digest_size How many bytes you want to fill digest with. digest must be pre-allocated
/// with at least this many bytes.
/// \param msg The message to hash, must have at least msg_size bytes allocated.
/// \param msg_size How many bytes are allocated for msg.
/// \param salt An additional, optional salt that will perform a secondary update after msg.
/// \param salt_size How big the salt is. If salt is NULL, then this value is ignored.
/// \return Returns a 0 on success and a 1 on failure.
int kang12_hash(unsigned char *digest, size_t digest_size, const unsigned char *msg, size_t msg_size,
                const unsigned char *salt, size_t salt_size);

#endif //RBC_VALIDATOR_HASH_H
