//
// Created by cp723 on 3/8/2019.
//

#ifndef HAMMING_BENCHMARK_UINT256_T_H
#define HAMMING_BENCHMARK_UINT256_T_H

#include <stdint.h>

#define UINT256_ZERO (uint256_t){0, 0, 0, 0}
#define UINT256_ONE (uint256_t){1, 0, 0, 0}
#define UINT256_NEG_ONE (uint256_t){0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}

typedef struct uint256_t {
    uint64_t limbs[4];
} uint256_t;

// Btwise operations
void uint256_and(uint256_t *rop, const uint256_t *op1, const uint256_t *op2);
void uint256_ior(uint256_t *rop, const uint256_t *op1, const uint256_t *op2);
void uint256_xor(uint256_t *rop, const uint256_t *op1, const uint256_t *op2);
void uint256_com(uint256_t *rop, const uint256_t *op1);
void uint256_shift_right(uint256_t *rop, const uint256_t* op1, unsigned long shift);
void uint256_shift_left(uint256_t *rop, const uint256_t* op1, unsigned long shift);

// Arithmetic
void uint256_neg(uint256_t *rop, const uint256_t *op1);
void uint256_add(uint256_t *rop, const uint256_t *op1, const uint256_t *op2);
unsigned long uint256_ctz(const uint256_t *op1);
int uint256_eq(const uint256_t* op1, const uint256_t* op2);

// Utility
void uint256_import(uint256_t *rop, const unsigned char *buffer);
void uint256_export(unsigned char *buffer, const uint256_t *rop);

#endif //HAMMING_BENCHMARK_UINT256_T_H
