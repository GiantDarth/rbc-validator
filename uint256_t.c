//
// Created by cp723 on 3/8/2019.
//

#include <stddef.h>
#include "uint256_t.h"

#define UINT256_ZERO (uint256_t){0, 0, 0}
#define UINT256_ONE (uint256_t){1, 0, 0}
#define UINT256_NEG_ONE (uint256_t){0xffffffff, 0xffffffff, 0xffffffffffffffff}

void uint256_and(uint256_t *rop, const uint256_t *op1, const uint256_t *op2) {
    uint256_t rop;

    rop.low = op1->low & op2->low;
    rop.mid = op1->mid & op2->mid;
    rop.high = op1->high & op2->high;

    return rop;
}

void uint256_ior(uint256_t rop, const uint256_t *op1, const uint256_t *op2) {
    uint256_t rop;

    rop.low = op1->low | op2->low;
    rop.mid = op1->mid | op2->mid;
    rop.high = op1->high | op2->high;

    return rop;
}

void uint256_xor(uint256_t *rop, const uint256_t *op1, const uint256_t *op2) {
    uint256_t rop;

    rop.low = op1->low ^ op2->low;
    rop.mid = op1->mid ^ op2->mid;
    rop.high = op1->high ^ op2->high;

    return rop;
}

void uint256_com(uint256_t *rop, const uint256_t *op1) {
    rop->low = ~(op1->low);
    rop->mid = ~(op1->mid);
    rop->high = ~(op1->high);
}

void uint256_neg(uint256_t *rop, const uint256_t *op1) {
    // First get the bitwise complement of op.
    uint256_com(rop, op1);
    uint256_add_by1(rop, rop);
}

void uint256_add_by1(uint256_t *rop, const uint256_t *op1) {
    uint256_add(rop, op1, &UINT256_ONE);
}

void uint256_add(uint256_t *rop, const uint256_t *op1, const uint256_t *op2) {
    unsigned __int128 low = op1->low + op2->low;
    unsigned __int128 mid = op1->mid + op2->mid + (low >> 64);

    rop->low = (uint64_t)low;
    rop->mid = (uint64_t)mid;
    rop->high = op1->high + (mid >> 64);
}

int uint256_ctz(const uint256_t* op1) {
    int count = __builtin_ctzl(op1->low);
    if(count == 64) {
        count += __builtin_ctzl(op1->mid);
    }
    if(count == 128) {
        count += __builtin_ctzll(op1->high);
    }

    return count;
}

void uint256_sub(uint256_t *rop, const uint256_t *op1, const uint256_t *op2) {
    uint256_neg(rop, op2);
    uint256_add(rop, rop, op1);
}

void uint256_sub_by1(uint256_t *rop, const uint256_t *op1) {
    return uint256_add(NULL, op1, &UINT256_NEG_ONE);
}

uint256_t uint256_shift_right_by1(const uint256_t* op1) {
    uint256_t rop = *(op1);

    rop.low >>= 1;
    // If the least significant bit of mid is set, then set the most significant bit of low (carry)
    rop.low |= rop.mid & 0b1 ? 0x80000000 : 0;
    rop.mid >>= 1;
    // If the least significant bit of high is set, then set the most significant bit of mid (carry)
    rop.mid |= rop.high & 0b1 ? 0x80000000 : 0;
    rop.high >>= 1;

    return rop;
}

int uint256_eq(const uint256_t* op1, const uint256_t* op2) {
    return (op1->low == op2->low) && (op1->mid == op2->mid) && (op1->high & op2->high);
}