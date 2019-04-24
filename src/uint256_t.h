//
// Created by cp723 on 3/8/2019.
//

#ifndef HAMMING_BENCHMARK_UINT256_T_H
#define HAMMING_BENCHMARK_UINT256_T_H

#include <stdint.h>

#define UINT256_ZERO (uint256_t){0, 0, 0, 0}
#define UINT256_ONE (uint256_t){1, 0, 0, 0}
#define UINT256_NEG_ONE (uint256_t){0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff}

#define UINT256_LIMBS_SIZE 4

typedef struct uint256_t {
    uint64_t limbs[UINT256_LIMBS_SIZE];
} uint256_t;

/// Set an unsigned long long to a uint256 struct.
/// \param rop A pointer to an uint256_t that will be modified.
/// \param value The value to set uint256_t to.
void uint256_set_ui(uint256_t *rop, unsigned long long value);

// Btwise operations
/// Perform a bitwise AND between op1 and op2 and set to rop.
/// \param rop The resultant value to be modified.
/// \param op1 The first operand.
/// \param op2 The second operand.
void uint256_and(uint256_t *rop, const uint256_t *op1, const uint256_t *op2);
/// Perform a bitwise OR between op1 and op2 and set to rop.
/// \param rop The resultant value to be modified.
/// \param op1 The first operand.
/// \param op2 The second operand.
void uint256_ior(uint256_t *rop, const uint256_t *op1, const uint256_t *op2);
/// Perform a bitwise XOR between op1 and op2 and set to rop.
/// \param rop The resultant value to be modified.
/// \param op1 The first operand.
/// \param op2 The second operand.
void uint256_xor(uint256_t *rop, const uint256_t *op1, const uint256_t *op2);
/// Perform a bitwise NOT (complement) of op1 and set to rop.
/// \param rop The resultant value to be modified.
/// \param op1 The first operand.
void uint256_com(uint256_t *rop, const uint256_t *op1);
/// Perform a logical right shift of op1 by 'shift' bits and set to rop.
/// \param rop The resultant value to be modified.
/// \param op1 The first operand.
/// \param shift The # of bits to shift by. Passing in a negative value is undefined.
void uint256_shift_right(uint256_t *rop, const uint256_t* op1, int shift);
/// Perform a logical left shift of op1 by 'shift' bits and set to rop.
/// \param rop The resultant value to be modified.
/// \param op1 The first operand.
/// \param shift The # of bits to shift by. Passing in a negative value is undefined.
void uint256_shift_left(uint256_t *rop, const uint256_t* op1, int shift);

// Arithmetic
/// Perform a 2's complement negation of op1 and set to rop.
/// \param rop The resultant value to be modified.
/// \param op1 The first operand.
void uint256_neg(uint256_t *rop, const uint256_t *op1);
/// Add op1 and op2 and set to rop.
/// \param rop The resultant value to be modified.
/// \param op1 The first operand.
/// \param op2 The second operand.
/// \return Returns the carry out (in the case of overflow).
unsigned char uint256_add(uint256_t *rop, const uint256_t *op1, const uint256_t *op2);
/// Count the # of trailing zeroes starting from the least significant bit.
/// If op1 is 0, then it is defined as 256.
/// \param op1 The first operand.
/// \return The # of trailing bits of op1.
int uint256_ctz(const uint256_t *op1);
/// Compare op1 to op2.
/// \param op1 The first operand.
/// \param op2 The second operand.
/// \return Returns a 1 if op1 > op2, -1 if op1 < op2, or 0 if op1 == op2.
int uint256_cmp(const uint256_t* op1, const uint256_t* op2);

// Utility
/// Reads in an array of unsigned char's, where the first byte is the
/// most significant word and the most significant byte.
/// \param rop The resultant value to be modified.
/// \param buffer The array to read from. Must be at least 32 bytes allocated.
void uint256_import(uint256_t *rop, const unsigned char *buffer);
/// Convert rop to an array of unsigned char's, where the first byte is the
/// most significant word and the most significant byte.
/// \param buffer The array to write to. Must be at least 32 bytes allocated.
/// \param rop The value to read from.
void uint256_export(unsigned char *buffer, const uint256_t *rop);

#endif //HAMMING_BENCHMARK_UINT256_T_H
