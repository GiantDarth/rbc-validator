//
// Created by cp723 on 3/14/2019.
//

// Adapted from the Intel whitepaper:
// https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf

// AES-NI and SSE intrinsincs
#include "aes256-ni.h"

#include <wmmintrin.h>

// How many rounds do for AES-256 encryption/decryption
#define NUM_OF_ROUNDS 14

static inline void KEY_256_ASSIST_1(__m128i *tmp1, __m128i *tmp2) {
    __m128i tmp4;

    *tmp2 = _mm_shuffle_epi32(*tmp2, 0xff);

    tmp4 = _mm_slli_si128(*tmp1, 0x4);
    *tmp1 = _mm_xor_si128(*tmp1, tmp4);

    tmp4 = _mm_slli_si128(tmp4, 0x4);
    *tmp1 = _mm_xor_si128(*tmp1, tmp4);

    tmp4 = _mm_slli_si128(tmp4, 0x4);
    *tmp1 = _mm_xor_si128(*tmp1, tmp4);
    *tmp1 = _mm_xor_si128(*tmp1, *tmp2);
}

static inline void KEY_256_ASSIST_2(__m128i *tmp1, __m128i *tmp3) {
    __m128i tmp2, tmp4;

    tmp4 = _mm_aeskeygenassist_si128(*tmp1, 0x0);
    tmp2 = _mm_shuffle_epi32(tmp4, 0xaa);

    tmp4 = _mm_slli_si128(*tmp3, 0x4);
    *tmp3 = _mm_xor_si128(*tmp3, tmp4);

    tmp4 = _mm_slli_si128(tmp4, 0x4);
    *tmp3 = _mm_xor_si128(*tmp3, tmp4);

    tmp4 = _mm_slli_si128(tmp4, 0x4);
    *tmp3 = _mm_xor_si128(*tmp3, tmp4);
    *tmp3 = _mm_xor_si128(*tmp3, tmp2);
}

void aes256_key_expansion(__m128i *key_schedule, const unsigned char *key){
    __m128i tmp1, tmp2, tmp3;

    tmp1 = _mm_loadu_si128((const __m128i*) key);
    tmp3 = _mm_loadu_si128((const __m128i*) (key + 16));

    key_schedule[0] = tmp1;
    key_schedule[1] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x01);
    KEY_256_ASSIST_1(&tmp1, &tmp2);
    key_schedule[2] = tmp1;

    KEY_256_ASSIST_2(&tmp1, &tmp3);
    key_schedule[3] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x02);
    KEY_256_ASSIST_1(&tmp1, &tmp2);
    key_schedule[4] = tmp1;

    KEY_256_ASSIST_2(&tmp1, &tmp3);
    key_schedule[5] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x04);
    KEY_256_ASSIST_1(&tmp1, &tmp2);
    key_schedule[6] = tmp1;

    KEY_256_ASSIST_2(&tmp1, &tmp3);
    key_schedule[7] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x08);
    KEY_256_ASSIST_1(&tmp1, &tmp2);
    key_schedule[8] = tmp1;

    KEY_256_ASSIST_2(&tmp1, &tmp3);
    key_schedule[9] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x10);
    KEY_256_ASSIST_1(&tmp1, &tmp2);
    key_schedule[10] = tmp1;

    KEY_256_ASSIST_2(&tmp1, &tmp3);
    key_schedule[11] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x20);
    KEY_256_ASSIST_1(&tmp1, &tmp2);
    key_schedule[12] = tmp1;

    KEY_256_ASSIST_2(&tmp1, &tmp3);
    key_schedule[13] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x40);
    KEY_256_ASSIST_1(&tmp1, &tmp2);
    key_schedule[14] = tmp1;
}

aes256_enc_key_scheduler* aes256_enc_key_scheduler_create() {
    aes256_enc_key_scheduler *key_scheduler;
    if((key_scheduler = malloc(sizeof(*key_scheduler))) == NULL) {
        return NULL;
    }

    if((key_scheduler->scheduler = malloc(32 * (NUM_OF_ROUNDS + 1))) == NULL) {
        free(key_scheduler);
        return NULL;
    }

    return key_scheduler;
}

void aes256_enc_key_scheduler_destroy(aes256_enc_key_scheduler *key_scheduler) {
    free(key_scheduler->scheduler);
    free(key_scheduler);
}

void aes256_enc_key_scheduler_update(aes256_enc_key_scheduler *key_scheduler, const unsigned char *key) {
    aes256_key_expansion(key_scheduler->scheduler, key);
}

/// Allocate a key_scheduler meant for AES-256 decryption
/// \return Returns a memory allocated pointer to a aes256_dec_key_scheduler, or NULL if something went wrong.
aes256_dec_key_scheduler* aes256_dec_key_scheduler_create() {
    aes256_dec_key_scheduler *key_scheduler;
    if((key_scheduler = malloc(sizeof(*key_scheduler))) == NULL) {
        return NULL;
    }

    if((key_scheduler->scheduler = malloc(32 * (NUM_OF_ROUNDS + 1))) == NULL) {
        free(key_scheduler);
        return NULL;
    }

    return key_scheduler;
}

void aes256_dec_key_scheduler_destroy(aes256_dec_key_scheduler *key_scheduler) {
    free(key_scheduler->scheduler);
    free(key_scheduler);
}

void aes256_dec_key_scheduler_update(aes256_dec_key_scheduler *key_scheduler, const unsigned char *key) {
    aes256_key_expansion(key_scheduler->scheduler, key);
}


int aes256_ecb_encrypt(unsigned char *cipher, aes256_enc_key_scheduler *key_scheduler,
        const unsigned char *msg, size_t msg_len) {
    __m128i tmp;
    size_t block_count = msg_len / 16;

    // If msg_len is not a multiple of 16, then throw an error
    if(msg_len % 16) {
        return 1;
    }

    for(size_t i = 0; i < block_count; ++i) {
        tmp = _mm_loadu_si128(&((__m128i*)msg)[i]);
        tmp = _mm_xor_si128(tmp, key_scheduler->scheduler[0]);

        for(int j = 1; j < NUM_OF_ROUNDS; ++j) {
            tmp = _mm_aesenc_si128(tmp, key_scheduler->scheduler[j]);
        }

        tmp = _mm_aesenclast_si128(tmp, key_scheduler->scheduler[NUM_OF_ROUNDS]);
        _mm_storeu_si128(&((__m128i*)cipher)[i], tmp);
    }

    return 0;
}

int aes256_ecb_decrypt(aes256_dec_key_scheduler *key_scheduler,
                       unsigned char *cipher, size_t cipher_len) {
    __m128i tmp;
    size_t block_count = cipher_len / 16;

    // If msg_len is not a multiple of 16, then throw an error
    if(cipher_len % 16) {
        return 1;
    }

    for(size_t i = 0; i < block_count; ++i) {
        tmp = _mm_loadu_si128(&((__m128i*)cipher)[i]);
        tmp = _mm_xor_si128(tmp, key_scheduler->scheduler[0]);

        for(int j = 1; j < NUM_OF_ROUNDS; ++j) {
            tmp = _mm_aesdec_si128(tmp, key_scheduler->scheduler[j]);
        }

        tmp = _mm_aesdeclast_si128(tmp, key_scheduler->scheduler[NUM_OF_ROUNDS - 1]);
        _mm_storeu_si128(&((__m128i*)cipher)[i], tmp);
    }

    return 0;
}