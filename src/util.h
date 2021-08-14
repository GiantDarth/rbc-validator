//
// Created by cp723 on 2/7/2019.
//

#ifndef HAMMING_BENCHMARK_UTIL_H
#define HAMMING_BENCHMARK_UTIL_H

#include <stdio.h>

/// Parse an individual hexadecimal character to an integer 0 to 15.
/// \param hex_char An individual hexadecimal character.
/// \return Return 0 to 15 depending on the value of hex_char, else return -1 on an invalid
/// character.
int parse_hex_char(char hex_char);
int unparse_hex_char(unsigned char value, int lower);

/// Print out a raw byte array as hexadecimal.
/// \param stream An IO stream to output to.
/// \param array An allocated byte array to print.
/// \param count The # of bytes to print from array.
void fprint_hex(FILE* stream, const unsigned char* array, size_t count);

/// Unparse a hex string to a byte array. The hex string is assumed to be null-terminated.
/// \param array An allocated byte array to parse to.
/// \param hex_string A null-terminated hex string.
/// \return Returns 0 on success, 1 if the string contains any invalid characters, or 2
/// if the hex string length is odd.
int parse_hex(unsigned char* array, const char* hex_string);

#endif  // HAMMING_BENCHMARK_UTIL_H
