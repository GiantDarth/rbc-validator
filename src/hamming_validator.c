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

#define KEY_SIZE 32
#define BLOCK_SIZE 16

const char *argp_program_version = "hamming_validator OpenMP 0.1.0";
const char *argp_program_bug_address = "<cp723@nau.edu, Chris.Coffey@nau.edu>";
error_t argp_err_exit_status = ERROR_CODE_FAILURE;

static char args_doc[] = "CIPHER KEY UUID\n-r/--random -c/--cipher-mismatches=value";
static char prog_desc[] = "Given an AES-256 KEY and a CIPHER from an unreliable source,"
                          " progressively corrupt it by a certain number of bits until"
                          " a matching corrupted key is found. The matching key will be"
                          " sent to stdout.\n\nThis implementation uses MPI.\v"

                          "The CIPHER, passed in as hexadecimal, is assumed to have been"
                          " generated in ECB mode, meaning given a 128-bit UUID, this"
                          " should be 128-bits long as well.\n\n"

                          "The original KEY, passed in as hexadecimal, is corrupted by"
                          " a certain number of bits and compared against CIPHER. Only"
                          " AES-256 keys are currently supported.\n\n"

                          "The UUID, passed in canonical form is the message that both"
                          " sources encrypt and is previously agreed upon.";

struct arguments {
    int verbose, benchmark, random;
    char *cipher_hex, *key_hex, *uuid_hex;
    int mismatches, cipher_mismatches, threads;
};

static struct argp_option options[] = {
    {0, 0, 0, 0, "General Options:"},
    {"benchmark", 'b', 0, 0, "Don't cut out early when key is found."},
    {"mismatches", 'm', "value", 0, "The # of bits of corruption to test against. Defaults to"
                                    " -1. If negative, then it will start from 0 and"
                                    " continuously increase them up until the size of the key"
                                    " in bits."},
    {"threads", 't', "count", 0, "How many worker threads to use. Defaults to 0. If set to 0,"
                                 " then the number of threads used will be detected by the"
                                 " system." },
    {0, 0, 0, 0, "Random Mode Options:"},
    {"random", 'r', 0, 0, "Instead of using arguments, randomly generate CIPHER, KEY, and"
                          " UUID."},
    {"cipher-mismatches", 'c', "value", 0, "The # of bits to corrupt the key by. This only"
                                           " makes sense in random mode."},
    {0, 0, 0, 0, "Diagnostic Options:"},
    {"verbose", 'v', 0, 0, "Produces verbose output and time taken to stderr."},
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
        case 'r':
            arguments->random = 1;
            break;
        case 'm':
            errno = 0;
            value = strtol(arg, &endptr, 10);

            if((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                    || (errno && value == 0)) {
                argp_failure(state, ERROR_CODE_FAILURE, errno, "--mismatches");
            }

            if(*endptr != '\0') {
                argp_error(state, "--mismatches contains invalid characters.\n");
            }

            if (value > KEY_SIZE * 8) {
                fprintf(stderr, "--mismatches cannot exceed the key size for AES-256"
                                " in bits.\n");
            }

            arguments->mismatches = (int)value;

            break;
        case 'c':
            errno = 0;
            value = strtol(arg, &endptr, 10);

            if((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                    || (!errno && value == 0)) {
                argp_failure(state, ERROR_CODE_FAILURE, errno, "--cipher-mismatches");
            }

            if(*endptr != '\0') {
                argp_error(state, "--cipher-mismatches contains invalid characters.\n");
            }

            if (value > KEY_SIZE * 8) {
                fprintf(stderr, "--cipher-mismatches cannot exceed the key size for AES-256"
                                " in bits.\n");
            }

            arguments->cipher_mismatches = (int)value;

            break;
        case 't':
            errno = 0;
            value = strtol(arg, &endptr, 10);

            if((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                    || (errno && value == 0)) {
                argp_failure(state, ERROR_CODE_FAILURE, errno, "--threads");
            }

            if(*endptr != '\0') {
                argp_error(state, "--threads contains invalid characters.\n");
            }

            if(value > omp_get_thread_limit()) {
                argp_error(state, "--threads exceeds program thread limit.\n");
            }

            arguments->threads = (int)value;

            break;
        case ARGP_KEY_ARG:
            switch(state->arg_num) {
                case 0:
                    if(strlen(arg) != BLOCK_SIZE * 2) {
                        argp_error(state, "CIPHER not equivalent to 128-bits long.\n");
                    }
                    arguments->cipher_hex = arg;
                    break;
                case 1:
                    if(strlen(arg) != KEY_SIZE * 2) {
                        argp_error(state, "Only AES-256 keys supported. KEY not"
                                          " equivalent to 256-bits long.\n");
                    }
                    arguments->key_hex = arg;
                    break;
                case 2:
                    if(strlen(arg) != 36) {
                        argp_error(state, "UUID not 36 characters long.\n");
                    }
                    arguments->uuid_hex = arg;
                    break;
                default:
                    argp_usage(state);
            }
            break;
        case ARGP_KEY_NO_ARGS:
            if(!arguments->random) {
                argp_usage(state);
            }
            break;
        case ARGP_KEY_END:
            if(arguments->random && arguments->cipher_mismatches < 0) {
                argp_error(state, "--cipher-mismatches must be set and non-negative when using"
                                  " random mode.\n");
            }

            break;
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
/// \param benchmark If benchmark mode is set to a non-zero value, then continue even if found.
/// \return Returns a 1 if found or a 0 if not. Returns a -1 if an error has occurred.
int gmp_validator(const uint256_t *starting_perm, const uint256_t *last_perm, const unsigned char *key,
        size_t key_size, uuid_t userId, const unsigned char *auth_cipher, const int* signal,
        int benchmark) {
    // Declaration
    unsigned char *corrupted_key;
    unsigned char cipher[BLOCK_SIZE];
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

    if(benchmark) {
        // While we haven't reached the end of iteration
        while(!uint256_key_iter_end(iter)) {
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
            }

            uint256_key_iter_next(iter);
        }
    }
    else {
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
                fprint_hex(stdout, corrupted_key, KEY_SIZE);
                printf("\n");
                break;
            }

            uint256_key_iter_next(iter);
        }
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
    struct arguments arguments;
    static struct argp argp = {options, parse_opt, args_doc, prog_desc};

    gmp_randstate_t randstate;

    uuid_t userId;
    char uuid_str[37];

    unsigned char *key;
    unsigned char *corrupted_key;
    unsigned char auth_cipher[BLOCK_SIZE];

    aes256_enc_key_scheduler *key_scheduler;

    int mismatch, ending_mismatch;

    double startTime;
    int found, subfound, signal, error;

    // Memory allocation
    if ((key = malloc(sizeof(*key) * KEY_SIZE)) == NULL) {
        perror("ERROR");
        return ERROR_CODE_FAILURE;
    }

    if ((corrupted_key = malloc(sizeof(*corrupted_key) * KEY_SIZE)) == NULL) {
        perror("ERROR");
        free(key);
        return ERROR_CODE_FAILURE;
    }

    if ((key_scheduler = aes256_enc_key_scheduler_create()) == NULL) {
        perror("ERROR");
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
    arguments.cipher_mismatches = -1;

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    // Initialize values
    // Set the gmp prng algorithm and set a seed based on the current time
    gmp_randinit_default(randstate);
    gmp_randseed_ui(randstate, (unsigned long)time(NULL));

    mismatch = 0;
    ending_mismatch = KEY_SIZE * 8;

    // If a mismatch argument was provided, set the validation range to only use that instead.
    if (arguments.mismatches >= 0) {
        mismatch = arguments.mismatches;
        ending_mismatch = arguments.mismatches;
    }

    if (arguments.random) {
        fprintf(stderr, "WARNING: Random mode set. All three arguments will be ignored and randomly"
                        " generated ones will be used in their place.\n");

        uuid_generate(userId);

        get_random_key(key, KEY_SIZE, randstate);
        get_random_corrupted_key(corrupted_key, key, arguments.cipher_mismatches, KEY_SIZE, randstate);

        aes256_enc_key_scheduler_update(key_scheduler, corrupted_key);
        if (aes256_ecb_encrypt(auth_cipher, key_scheduler, userId, sizeof(uuid_t))) {
            // Cleanup
            aes256_enc_key_scheduler_destroy(key_scheduler);
            free(corrupted_key);
            free(key);

            return ERROR_CODE_FAILURE;
        }
    }
    else {
        switch(parse_hex(auth_cipher, arguments.cipher_hex)) {
            case 1:
                fprintf(stderr, "ERROR: CIPHER had non-hexadecimal characters.\n");
                return EINVAL;
            case 2:
                fprintf(stderr, "ERROR: CIPHER did not have even length.\n");
                return EINVAL;
            default:
                break;
        }

        switch(parse_hex(key, arguments.key_hex)) {
            case 1:
                fprintf(stderr, "ERROR: KEY had non-hexadecimal characters.\n");
                return EINVAL;
            case 2:
                fprintf(stderr, "ERROR: KEY did not have even length.\n");
                return EINVAL;
            default:
                break;
        }

        if (uuid_parse(arguments.uuid_hex, userId) < 0) {
            fprintf(stderr, "ERROR: UUID not in canonical form.\n");
            return EINVAL;
        }
    }

    if (arguments.verbose) {
        // Convert the uuid to a string for printing
        uuid_unparse(userId, uuid_str);

        fprintf(stderr, "INFO: Using UUID:                                 %s\n", uuid_str);

        fprintf(stderr, "INFO: Using AES-256 Key:                          ");
        fprint_hex(stderr, key, KEY_SIZE);
        fprintf(stderr, "\n");

        if(arguments.random) {
            fprintf(stderr, "INFO: Using AES-256 Corrupted Key (%d mismatches): ",
                    arguments.cipher_mismatches);
            fprint_hex(stderr, corrupted_key, KEY_SIZE);
            fprintf(stderr, "\n");
        }

        fprintf(stderr, "INFO: AES-256 Authentication Cipher:              ");
        fprint_hex(stderr, auth_cipher, BLOCK_SIZE);
        fprintf(stderr, "\n");
    }

    startTime = omp_get_wtime();
    found = 0;
    signal = 0;
    error = 0;

    if (arguments.threads > 0) {
        omp_set_num_threads(arguments.threads);
    }

    for (; mismatch <= ending_mismatch && !found; mismatch++) {
        if(arguments.verbose) {
            fprintf(stderr, "INFO: Checking a hamming distance of %d...\n", mismatch);
        }

#pragma omp parallel
        {
            uint256_t starting_perm, ending_perm;

            uint256_get_perm_pair(&starting_perm, &ending_perm, (size_t) omp_get_thread_num(),
                                  (size_t) omp_get_num_threads(), mismatch, KEY_SIZE);

            subfound = gmp_validator(&starting_perm, &ending_perm, key, KEY_SIZE, userId,
                    auth_cipher, &signal, arguments.benchmark);
            // If the result is positive, set the "global" found to 1. Will cause the other threads to
            // prematurely stop.
            if (subfound > 0) {
#pragma omp critical
                {
                    found = 1;
                    signal = 1;
                };
            }
                // If the result is negative, set a flag that an error has occurred, and stop the other threads.
                // Will cause the other threads to prematurely stop.
            else if (subfound < 0) {
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
        fprintf(stderr, "INFO: Clock time: %f s\n", duration);
        fprintf(stderr, "INFO: Found: %d\n", found);
    }
  
    // Cleanup
    aes256_enc_key_scheduler_destroy(key_scheduler);
    free(corrupted_key);
    free(key);

    return found ? ERROR_CODE_FOUND : ERROR_CODE_NOT_FOUND;
}