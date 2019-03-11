//
// Created by cp723 on 3/8/2019.
//

#include <stddef.h>
#include <string.h>
#include <x86intrin.h>
#include "uint256_t.h"

void uint256_and(uint256_t *rop, const uint256_t *op1, const uint256_t *op2) {
    for(int i = 0; i < 4; ++i) {
        rop->limbs[i] = op1->limbs[i] & op2->limbs[i];
    }
}

void uint256_ior(uint256_t *rop, const uint256_t *op1, const uint256_t *op2) {
    for(int i = 0; i < 4; ++i) {
        rop->limbs[i] = op1->limbs[i] | op2->limbs[i];
    }
}

void uint256_xor(uint256_t *rop, const uint256_t *op1, const uint256_t *op2) {
    for(int i = 0; i < 4; ++i) {
        rop->limbs[i] = op1->limbs[i] ^ op2->limbs[i];
    }
}

void uint256_com(uint256_t *rop, const uint256_t *op1) {
    for(int i = 0; i < 4; ++i) {
        rop->limbs[i] = ~(op1->limbs[i]);
    }
}

void uint256_neg(uint256_t *rop, const uint256_t *op1) {
    // First get the bitwise complement of op.
    uint256_com(rop, op1);
    uint256_add(rop, rop, &UINT256_ONE);
}

void uint256_shift_right(uint256_t *rop, const uint256_t* op1, unsigned long shift) {
    memcpy(rop->limbs, op1->limbs, 32);

    for(unsigned long i = 0; i < shift; ++i) {
        for(int j = 0; j < 3; ++j) {
            rop->limbs[j] >>= 1;
            // If the least significant bit of high is set, then set the most significant bit of low (carry)
            rop->limbs[j] |= (rop->limbs[j + 1] & 0b1) << 63;
        }
        rop->limbs[3] >>= 1;
    }
}

void uint256_shift_left(uint256_t *rop, const uint256_t* op1, unsigned long shift) {
    memcpy(rop->limbs, op1->limbs, 32);

    for(unsigned long i = 0; i < shift; ++i) {
        for(int j = 3; j > 0; --j) {
            rop->limbs[j] <<= 1;
            // If the least significant bit of high is set, then set the most significant bit of low (carry)
            rop->limbs[j] |= (rop->limbs[j - 1] >> 63) & 0b1;
        }
        rop->limbs[0] <<= 1;
    }
}


unsigned char uint256_add(uint256_t *rop, const uint256_t *op1, const uint256_t *op2) {
    unsigned char carry = 0;
    for(int i = 0; i < 4; ++i) {
        carry = _addcarry_u64(carry, op1->limbs[i], op2->limbs[i], (unsigned long long*)&(rop->limbs[i]));
    }

    return carry;
}

unsigned long uint256_ctz(const uint256_t *op1) {
    unsigned long count = __builtin_ctzll(op1->limbs[0]);
    int count_limit = 64;

    for(int i = 1; count == count_limit && i < 4; ++i) {
        count += __builtin_ctzll(op1->limbs[i]);
        count_limit += 64;
    }

    return count;
}

int uint256_eq(const uint256_t* op1, const uint256_t* op2) {
    return (op1->limbs[0] == op2->limbs[0]) && (op1->limbs[1] == op2->limbs[1])
        && (op1->limbs[2] == op2->limbs[2]) && (op1->limbs[3] == op2->limbs[3]);
}

void uint256_import(uint256_t *rop, const unsigned char *buffer) {
    int b = 0;

    *rop = UINT256_ZERO;

    for(int i = 0; i < 4; ++i) {
        for(int shift = 56; shift >= 0; shift -= 8) {
            rop->limbs[i] |= (buffer[b++] << shift);
        }
    }
}

void uint256_export(unsigned char *buffer, const uint256_t *rop) {
    int b = 0;

    for(int i = 3; i >= 0; --i) {
        for(int shift = 56; shift >= 0; shift -= 8) {
            buffer[b++] = (unsigned char)(rop->limbs[i] >> shift);
        }
    }
}
