//
// Created by cp723 on 3/8/2019.
//

#ifndef HAMMING_BENCHMARK_UINT256_T_H
#define HAMMING_BENCHMARK_UINT256_T_H

#include <stdint.h>

typedef struct uint256_t {
    uint64_t low;
    uint64_t mid;
    unsigned __int128 high;
} uint256_t;

#endif //HAMMING_BENCHMARK_UINT256_T_H

// Btwise operations
void uint256_and(uint256_t *rop, const uint256_t *op1, const uint256_t *op2);
void uint256_ior(uint256_t rop, const uint256_t *op1, const uint256_t *op2);
void uint256_xor(uint256_t *rop, const uint256_t *op1, const uint256_t *op2);
void uint256_com(uint256_t *rop, const uint256_t *op1);

// Arithmetic
void uint256_neg(uint256_t *rop, const uint256_t *op1);
void uint256_add(uint256_t *rop, const uint256_t *op1, const uint256_t *op2);
void uint256_add_by1(uint256_t *rop, const uint256_t *op1);
int uint256_ctz(const uint256_t* op1);
void uint256_sub(uint256_t *rop, const uint256_t *op1, const uint256_t *op2);
void uint256_sub_by1(uint256_t *rop, const uint256_t *op1);
int uint256_eq(const uint256_t* op1, const uint256_t* op2);