//
// Created by cp723 on 3/14/2019.
//

// Adapted from the Intel whitepaper:
// https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf

// AES-NI and SSE intrinsincs
#include "aes256-ni_enc.h"

#include <wmmintrin.h>

// How many rounds do for AES-256 encryption/decryption
#define NUM_OF_ROUNDS 14

static inline void key256Assist1(__m128i* tmp1, __m128i* tmp2) {
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

static inline void key256Assist2(__m128i* tmp1, __m128i* tmp3) {
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

void aes256EncKeyExpansion(__m128i* key_schedule, const unsigned char* key) {
    __m128i tmp1, tmp2, tmp3;

    tmp1 = _mm_loadu_si128((const __m128i*)key);
    tmp3 = _mm_loadu_si128((const __m128i*)(key + 16));

    key_schedule[0] = tmp1;
    key_schedule[1] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x01);
    key256Assist1(&tmp1, &tmp2);
    key_schedule[2] = tmp1;

    key256Assist2(&tmp1, &tmp3);
    key_schedule[3] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x02);
    key256Assist1(&tmp1, &tmp2);
    key_schedule[4] = tmp1;

    key256Assist2(&tmp1, &tmp3);
    key_schedule[5] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x04);
    key256Assist1(&tmp1, &tmp2);
    key_schedule[6] = tmp1;

    key256Assist2(&tmp1, &tmp3);
    key_schedule[7] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x08);
    key256Assist1(&tmp1, &tmp2);
    key_schedule[8] = tmp1;

    key256Assist2(&tmp1, &tmp3);
    key_schedule[9] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x10);
    key256Assist1(&tmp1, &tmp2);
    key_schedule[10] = tmp1;

    key256Assist2(&tmp1, &tmp3);
    key_schedule[11] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x20);
    key256Assist1(&tmp1, &tmp2);
    key_schedule[12] = tmp1;

    key256Assist2(&tmp1, &tmp3);
    key_schedule[13] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x40);
    key256Assist1(&tmp1, &tmp2);
    key_schedule[14] = tmp1;
}

int aes256EcbEncrypt(unsigned char* cipher, const unsigned char* key, const unsigned char* msg,
                     size_t msg_len) {
    __m128i tmp;
    size_t block_count = msg_len / AES_BLOCK_SIZE;

    __m128i scheduler[sizeof(__m128i) * (NUM_OF_ROUNDS + 1)];

    if (msg_len % AES_BLOCK_SIZE) {
        return 1;
    }

    aes256EncKeyExpansion(scheduler, key);

    for (size_t i = 0; i < block_count; ++i) {
        tmp = _mm_loadu_si128(&((__m128i*)msg)[i]);
        tmp = _mm_xor_si128(tmp, scheduler[0]);

        for (int j = 1; j < NUM_OF_ROUNDS; ++j) {
            tmp = _mm_aesenc_si128(tmp, scheduler[j]);
        }

        tmp = _mm_aesenclast_si128(tmp, scheduler[NUM_OF_ROUNDS]);
        _mm_storeu_si128(&((__m128i*)cipher)[i], tmp);
    }

    return 0;
}
