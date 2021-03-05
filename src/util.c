#include "util.h"

#include <stdio.h>
#include <string.h>

void fprint_hex(FILE *stream, const unsigned char *array, size_t count) {
    for(size_t i = 0; i < count; i++) {
        fprintf(stream, "%02x", array[i]);
    }
}

/// Parse an individual hexadecimal character to an integer 0 to 15.
/// \param hex_char An individual hexadecimal character.
/// \return Return 0 to 15 depending on the value of hex_char, else return -1 on an invalid character.
int parse_hex_char(char hex_char) {
    if(hex_char >= '0' && hex_char <= '9') {
        return hex_char - 48;
    }
    else if(hex_char >= 'A' && hex_char <= 'F') {
        return hex_char - 55;
    }
    else if(hex_char >= 'a' && hex_char <= 'f') {
        return hex_char - 87;
    }
    else {
        return -1;
    }
}

int parse_hex(unsigned char *array, const char *hex_string) {
    size_t i, b;
    int value;

    for(i = 0, b = 0; hex_string[b] != '\0'; i++) {
        if((value = parse_hex_char(hex_string[b++])) < 0) {
            return 1;
        }

        array[i] = (unsigned char)value << 4;

        // The length of hex string was odd
        if(hex_string[b] == '\0') {
            return 2;
        }

        if((value = parse_hex_char(hex_string[b++])) < 0) {
            return 1;
        }

        array[i] |= (unsigned char)value;
    }

    return 0;
}
