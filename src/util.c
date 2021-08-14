#include "util.h"

#include <stdio.h>
#include <string.h>

void fprint_hex(FILE* stream, const unsigned char* array, size_t count) {
    for (size_t i = 0; i < count; i++) {
        fprintf(stream, "%02x", array[i]);
    }
}

int parse_hex_char(char hex_char) {
    if (hex_char >= '0' && hex_char <= '9') {
        return hex_char - '0';
    } else if (hex_char >= 'A' && hex_char <= 'F') {
        return hex_char - 'A' + 10;
    } else if (hex_char >= 'a' && hex_char <= 'f') {
        return hex_char - 'a' + 10;
    } else {
        return -1;
    }
}

int unparse_hex_char(unsigned char value, int lower) {
    if (value < 16) {
        if (value < 10) {
            return value + '0';
        } else {
            if (lower) {
                return value + 'a' - 10;
            } else {
                return value + 'A' - 10;
            }
        }
    } else {
        return -1;
    }
}

int parse_hex(unsigned char* array, const char* hex_string) {
    size_t i, b;
    int value;

    for (i = 0, b = 0; hex_string[b] != '\0'; i++) {
        if ((value = parse_hex_char(hex_string[b++])) < 0) {
            return 1;
        }

        array[i] = (unsigned char)value << 4;

        // The length of hex string was odd
        if (hex_string[b] == '\0') {
            return 2;
        }

        if ((value = parse_hex_char(hex_string[b++])) < 0) {
            return 1;
        }

        array[i] |= (unsigned char)value;
    }

    return 0;
}
