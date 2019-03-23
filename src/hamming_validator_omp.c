//
// Created by cp723 on 2/7/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

#include <uuid/uuid.h>
#include <omp.h>
#include <argp.h>

#include "uint256_key_iter.h"
#include "aes256-ni.h"
#include "util.h"

#define ERROR_CODE_FOUND 0
#define ERROR_CODE_NOT_FOUND 1
#define ERROR_CODE_FAILURE 2

const char *argp_program_version = "hamming_validator_omp 0.1.0";
const char *argp_program_bug_address = "<cp723@nau.edu, Chris.Coffey@nau.edu>";

static char prog_desc[] = "Given an AES-256 key and a cipher from an unreliable source,"
                          " progressively corrupt it by a certain number of bits until"
                          " a matching corrupted key is found. The matching key will"
                          " sent to stdout.";

struct arguments {
    int verbose, benchmark;
    char *cipher_hex, *key_hex, *uuid_hex;
    int mismatches, threads;
};

static struct argp_option options[] = {
    {"verbose", 'v', 0, 0, "Produces verbose output and time taken to stderr."},
    {"benchmark", 'b', 0, 0, "Don't cut out early when key is found."},
    {"cipher", 'c', "hex", 0, "The cipher generated from a potentially unreliable source."
                              " If not provided, a random cipher will be generated and"
                              " key & uuid are ignored. The cipher is assumed to have"
                              " been generated in ECB mode, meaning given a 128-bit UUID,"
                              " this should be 128-bits long as well."},
    {"key", 'k', "hex", 0, "The original key to corrupt (in hexadecimal). If not provided,"
                           " a random key will be generated and cipher & uuid are ignored."
                           " Only AES-256 keys are currently supported."},
    {"uuid", 'u', "value", 0, "The UUID representing the user to encrypt (in canonical form)."
                              " If not provided, a random UUID will be generated and"
                              " cipher & key are ignored." },
    {"mismatches", 'm', "value", 0, "The # of bits to corrupt the key by. Defaults to -1."
                                    " If negative, then it will start from 0 and continuously"
                                    " increase them up until the size of the key in bits."},
    {"threads", 't', "count", 0, "The # of bits to corrupt the key by. Defaults to 0. If set"
                                 " to 0, then it the number of threads used will be detected"
                                 " by the system." },
    { 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    // Used for strtol
    char *endptr;
    long value;

    switch(key) {
        case 'v':
            arguments->verbose = 1;
            break;
        case 'b':
            arguments->benchmark = 1;
            break;
        case 'c':
            if(strlen(arg) != 32) {
                fprintf(stderr, "ERROR: Cipher not equivalent to 128-bits long.\n");
                return EINVAL;
            }
            arguments->cipher_hex = arg;
            break;
        case 'k':
            if(strlen(arg) != 64) {
                fprintf(stderr, "ERROR: Only AES-256 keys supported. Key not"
                                " equivalent to 256-bits long.\n");
                return EINVAL;
            }
            arguments->key_hex = arg;
            break;
        case 'u':
            if(strlen(arg) != 36) {
                fprintf(stderr, "ERROR: UUID not 36 characters long.\n");
                return EINVAL;
            }
            arguments->uuid_hex = arg;
            break;
        case 'm':
            errno = 0;
            value = strtol(arg, &endptr, 10);

            if((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                    || (!errno && value == 0)) {
                perror("ERROR");
                return EINVAL;
            }

            if(*endptr != '\0') {
                fprintf(stderr, "ERROR: mismatches contains invalid characters.\n");
                return EINVAL;
            }

            arguments->mismatches = (int)value;

            break;
        case 't':
            errno = 0;
            value = strtol(arg, &endptr, 10);

            if((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
               || (!errno && value == 0)) {
                perror("ERROR");
                return EINVAL;
            }

            if(*endptr != '\0') {
                fprintf(stderr, "ERROR: threads contains invalid characters.\n");
                return EINVAL;
            }

            arguments->threads = (int)value;

            break;
        case ARGP_KEY_NO_ARGS:
        case ARGP_KEY_END:
        case ARGP_KEY_INIT:
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

/// Given a starting permutation, iterate forward through every possible permutation until one that's matching
/// last_perm is found, or until a matching cipher is found.
/// \param starting_perm The permutation to start iterating from.
/// \param last_perm The final permutation to stop iterating at, inclusively.
/// \param key The original AES key.
/// \param key_size The key size in # of bytes, typically 32.
/// \param userId A uuid_t that's used to as the message to encrypt.
/// \param auth_cipher The authentication cipher to test against
/// \param signal A pointer to a shared value. Used to signal the function to prematurely leave.
/// \return Returns a 1 if found or a 0 if not. Returns a -1 if an error has occurred.
int gmp_validator(const uint256_t *starting_perm, const uint256_t *last_perm, const unsigned char *key,
        size_t key_size, uuid_t userId, const unsigned char *auth_cipher, const int* signal) {
    // Declaration
    unsigned char *corrupted_key;
    unsigned char cipher[sizeof(uuid_t)];
    int found = 0;

    uint256_key_iter *iter;
    aes256_enc_key_scheduler *key_scheduler;

    // Memory allocation
    if((corrupted_key = malloc(sizeof(*corrupted_key) * key_size)) == NULL) {
        perror("ERROR");
        return -1;
    }

    if((key_scheduler = aes256_enc_key_scheduler_create()) == NULL) {
        perror("ERROR");
        free(corrupted_key);

        return -1;
    }

    // Allocation and initialization
    if((iter = uint256_key_iter_create(key, starting_perm, last_perm)) == NULL) {
        perror("ERROR");
        aes256_enc_key_scheduler_destroy(key_scheduler);
        free(corrupted_key);

        return -1;
    }

    // While we haven't reached the end of iteration
    while(!uint256_key_iter_end(iter) && !(*signal)) {
        uint256_key_iter_get(iter, corrupted_key);
        aes256_enc_key_scheduler_update(key_scheduler, corrupted_key);

        // If encryption fails for some reason, break prematurely.
        if(aes256_ecb_encrypt(cipher, key_scheduler, userId, sizeof(uuid_t))) {
            found = -1;
            break;
        }

        // If the new cipher is the same as the passed in auth_cipher, set found to true and break
        if(memcmp(cipher, auth_cipher, sizeof(uuid_t)) == 0) {
            found = 1;
            break;
        }

        uint256_key_iter_next(iter);
    }

    // Cleanup
    aes256_enc_key_scheduler_destroy(key_scheduler);
    uint256_key_iter_destroy(iter);
    free(corrupted_key);

    return found;
}

/// OpenMP implementation
/// \return Returns a 0 on successfully finding a match, a 1 when unable to find a match,
/// and a 2 when a general error has occurred.
int main(int argc, char *argv[]) {
    const size_t KEY_SIZE = 32;

    struct arguments arguments;
    static struct argp argp = { options, parse_opt, 0, prog_desc };

    gmp_randstate_t randstate;

    uuid_t userId;
    char uuid_str[37];

    unsigned char *key;
    unsigned char *corrupted_key;
    unsigned char auth_cipher[sizeof(uuid_t)];

    aes256_enc_key_scheduler *key_scheduler;

    int mismatch, ending_mismatch, cipher_mismatch;

    double startTime;
    int found, signal, error;

    // Memory allocation
    if((key = malloc(sizeof(*key) * KEY_SIZE)) == NULL) {
        perror("Error");
        return ERROR_CODE_FAILURE;
    }

    if((corrupted_key = malloc(sizeof(*corrupted_key) * KEY_SIZE)) == NULL) {
        perror("Error");
        free(key);
        return ERROR_CODE_FAILURE;
    }

    if((key_scheduler = aes256_enc_key_scheduler_create()) == NULL) {
        perror("Error");
        free(corrupted_key);
        free(key);

        return ERROR_CODE_FAILURE;
    }

    memset(&arguments, 0, sizeof(arguments));
    arguments.cipher_hex = NULL;
    arguments.key_hex = NULL;
    arguments.uuid_hex = NULL;
    // Default to -1 for no mismatches provided, aka. go through all mismatches.
    arguments.mismatches = -1;

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    // Initialize values
    // Use this for a random # of bits to corrupt the key by if no mismatch is set.
    srand((unsigned int)time(NULL));
    // Set the gmp prng algorithm and set a seed based on the current time
    gmp_randinit_default(randstate);
    gmp_randseed_ui(randstate, (unsigned long)time(NULL));

    mismatch = 0;
    ending_mismatch = KEY_SIZE * 8;

    if(arguments.mismatches > ending_mismatch) {
        fprintf(stderr, "ERROR: Mismatches cannot exceed the key size for AES-256 in bits.\n");
        return EINVAL;
    }

    // If a mismatch argument was provided, set the validation range to only use that instead.
    if(arguments.mismatches >= 0) {
        mismatch = arguments.mismatches;
        ending_mismatch = arguments.mismatches;
        cipher_mismatch = arguments.mismatches;
    }
    else {
        cipher_mismatch = rand() % 5;
    }

    if(arguments.cipher_hex == NULL || arguments.key_hex == NULL || arguments.uuid_hex == NULL) {
        if(arguments.verbose) {
            printf("WARNING: cipher, key, or uuid were not provided. All three arguments are"
                   " ignored and randomly generating new ones in place.\n");
        }

        uuid_generate(userId);

        get_random_key(key, KEY_SIZE, randstate);
        get_random_corrupted_key(corrupted_key, key, cipher_mismatch, KEY_SIZE, randstate);

        aes256_enc_key_scheduler_update(key_scheduler, corrupted_key);
        if(aes256_ecb_encrypt(auth_cipher, key_scheduler, userId, sizeof(uuid_t))) {
            // Cleanup
            aes256_enc_key_scheduler_destroy(key_scheduler);
            free(corrupted_key);
            free(key);

            return ERROR_CODE_FAILURE;
        }
    }
    else {
        if(uuid_parse(arguments.uuid_hex, userId) < 0) {
            fprintf(stderr, "ERROR: UUID not in canonical form.\n");
            return EINVAL;
        }
    }

    if(arguments.verbose) {
        // Convert the uuid to a string for printing
        uuid_unparse(userId, uuid_str);

        printf("INFO: Using UUID:                                 %s\n", uuid_str);

        printf("INFO: Using AES-256 Key:                          ");
        print_hex(key, KEY_SIZE);
        printf("\n");

        printf("INFO: Using AES-256 Corrupted Key (%d mismatches): ", cipher_mismatch);
        print_hex(corrupted_key, KEY_SIZE);
        printf("\n");

        printf("INFO: AES-256 Authentication Cipher:              ");
        print_hex(auth_cipher, KEY_SIZE);
        printf("\n");
    }

    startTime = omp_get_wtime();
    found = 0;
    signal = 0;
    error = 0;

    if(arguments.threads > 0) {
        omp_set_num_threads(arguments.threads);
    }

#pragma omp parallel
    {
        uint256_t starting_perm, ending_perm;

        for(; mismatch <= ending_mismatch && !found; mismatch++) {
            uint256_get_perm_pair(&starting_perm, &ending_perm, (size_t)omp_get_thread_num(),
                                  (size_t)omp_get_num_threads(), mismatch, KEY_SIZE);

            int subfound = gmp_validator(&starting_perm, &ending_perm, key, KEY_SIZE, userId, auth_cipher, &signal);
            // If the result is positive, set the "global" found to 1. Will cause the other threads to
            // prematurely stop.
            if(subfound > 0) {
#pragma omp critical
                {
                    found = 1;
                    signal = 1;
                };
            }
                // If the result is negative, set a flag that an error has occurred, and stop the other threads.
                // Will cause the other threads to prematurely stop.
            else if(subfound < 0) {
                // Set the error flag, then set the signal to stop the other threads
#pragma omp critical
                {
                    error = 1;
                    signal = 1;
                };
            }
        }
    }

    // Check if an error occurred in one of the threads.
    if(error) {
        // Cleanup
        aes256_enc_key_scheduler_destroy(key_scheduler);
        free(corrupted_key);
        free(key);

        return EXIT_FAILURE;
    }

    double duration = omp_get_wtime() - startTime;

    if(arguments.verbose) {
        printf("INFO: Clock time: %f s\n", duration);
        printf("INFO: Found: %d\n", found);
    }
  
    // Cleanup
    aes256_enc_key_scheduler_destroy(key_scheduler);
    free(corrupted_key);
    free(key);

    return found ? ERROR_CODE_FOUND : ERROR_CODE_NOT_FOUND;
}