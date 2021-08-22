//
// Created by cp723 on 2/7/2019.
//

#ifndef RBC_VALIDATOR_UTIL_H_
#define RBC_VALIDATOR_UTIL_H_

#include <stdio.h>

/// Parse an individual hexadecimal character to an integer 0 to 15.
/// \param hex_char An individual hexadecimal character.
/// \return Return 0 to 15 depending on the value of hex_char, else return -1 on an invalid
/// character.
int parseHexChar(char hex_char);
int unparseHexChar(unsigned char value, int lower);

/// Print out a raw byte array as hexadecimal.
/// \param stream An IO stream to output to.
/// \param array An allocated byte array to print.
/// \param count The # of bytes to print from array.
void fprintHex(FILE* stream, const unsigned char* array, size_t count);

/// Unparse a hex string to a byte array. The hex string is assumed to be null-terminated.
/// \param array An allocated byte array to parse to.
/// \param hex_string A null-terminated hex string.
/// \return Returns 0 on success, 1 if the string contains any invalid characters, or 2
/// if the hex string length is odd.
int parseHex(unsigned char* array, const char* hex_string);

#endif  // RBC_VALIDATOR_UTIL_H_
