//
// Created by cp723 on 3/14/2019.
//

#ifndef HAMMING_BENCHMARK_AES256_NI_H
#define HAMMING_BENCHMARK_AES256_NI_H

#include <stddef.h>
#include <emmintrin.h>

typedef struct aes256_enc_key_scheduler {
    __m128i *scheduler;
} aes256_enc_key_scheduler;

typedef struct aes256_dec_key_scheduler {
    __m128i *scheduler;
} aes256_dec_key_scheduler;

/// Allocate a key_scheduler meant for AES-256 encryption
/// \return Returns a memory allocated pointer to a aes256_enc_key_scheduler, or NULL if something went wrong.
aes256_enc_key_scheduler* aes256_enc_key_scheduler_create();
/// Deallocate a passed in key_scheduler.
/// \param key_scheduler A pointer to an key_scheduler. Passing in a NULL pointer is undefined behavior.
void aes256_enc_key_scheduler_destroy(aes256_enc_key_scheduler *key_scheduler);
/// Update a decryption scheduler with a new AES-256 key.
/// \param key_scheduler A pointer to an aes256_enc_key_scheduler. Passing in a NULL pointer is undefined behavior.
/// \param key A pointer to at least 32 bytes of key data. Passing in a NULL pointer is undefined behavior.
void aes256_enc_key_scheduler_update(aes256_enc_key_scheduler *key_scheduler, const unsigned char *key);

/// Allocate a key_scheduler meant for AES-256 decryption
/// \return Returns a memory allocated pointer to a aes256_dec_key_scheduler, or NULL if something went wrong.
aes256_dec_key_scheduler* aes256_dec_key_scheduler_create();
/// Deallocate a passed in key_scheduler.
/// \param key_scheduler A pointer to a key_scheduler. Passing in a NULL pointer is undefined behavior.
void aes256_dec_key_scheduler_destroy(aes256_dec_key_scheduler *key_scheduler);
/// Update an encryption scheduler with a new AES-256 key.
/// \param key_scheduler A pointer to an aes256_dec_key_scheduler. Passing in a NULL pointer is undefined behavior.
/// \param key A pointer to at least 32 bytes of key data. Passing in a NULL pointer is undefined behavior.
void aes256_dec_key_scheduler_update(aes256_dec_key_scheduler *key_scheduler, const unsigned char *key);

/// Encrypts some message data using AES-256-ECB without padding
/// \param cipher The output encryption
/// \param key_scheduler A pointer to an aes256_enc_key_scheduler.
/// \param msg The message to be encrypted, designated to be msg_len bytes long.
/// \param msg_len Denotes the size of the message
/// \return Returns 0 on success or 1 on error.
int aes256_ecb_encrypt(unsigned char *cipher, aes256_enc_key_scheduler *key_scheduler,
        const unsigned char *msg, size_t msg_len);
/// Decrypts some cipher using AES-256-ECB without padding
/// \param msg The decrypted message, the same length as cipher_len.
/// \param key_scheduler A pointer to an aes256_dec_key_scheduler.
/// \param cipher An AES-256-ECB cipher without padding
/// \param cipher_len Denotes the size of the cipher (and decrypted message).
/// \return Returns 0 on success or 1 on error.
int aes256_ecb_decrypt(const unsigned char *msg, aes256_dec_key_scheduler *key_scheduler,
        unsigned char *cipher, size_t cipher_len);

#endif // HAMMING_BENCHMARK_AES256_NI_H
