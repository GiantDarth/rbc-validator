//
// Created by cp723 on 2/7/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <mpi.h>

#include <uuid/uuid.h>
#include <gmp.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <argp.h>

#include "uint256_key_iter.h"
#include "aes256-ni.h"
#include "util.h"

#define ERROR_CODE_FOUND 0
#define ERROR_CODE_NOT_FOUND 1
#define ERROR_CODE_FAILURE 2

#define KEY_SIZE 32
#define BLOCK_SIZE 16

const char *argp_program_version = "hamming_validator MPI 0.1.0";
const char *argp_program_bug_address = "<cp723@nau.edu, Chris.Coffey@nau.edu>";
error_t argp_err_exit_status = ERROR_CODE_FAILURE;

static char args_doc[] = "CIPHER KEY UUID\n-r/--random -m/--mismatches=value";
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
    int verbose, benchmark, random, only_given;
    char *cipher_hex, *key_hex, *uuid_hex;
    int mismatches;
};

static struct argp_option options[] = {
    {"benchmark", 'b', 0, 0, "Don't cut out early when key is found."},
    {"mismatches", 'm', "value", 0, "The largest # of bits of corruption to test against,"
                                    " inclusively. Defaults to -1. If negative, then the"
                                    " size of key in bits will be the limit. If in random,"
                                    " then this will also be used to corrupt the random key"
                                    " by the same # of bits; for this reason, it must be set"
                                    " and non-negative when in random mode."},
    // Uses a non-printable key to signify that this is a long-only option
    {"only-given", 1000, 0, 0, "Only test the given mismatch, instead of progressing from 0 to"
                               " --mismatches. This is only valid when --mismatches is set and"
                               " non-negative."},
    {"random", 'r', 0, 0, "Instead of using arguments, randomly generate CIPHER, KEY, and"
                          " UUID. This must be accompanied by --mismatches, since it is used to"
                          " corrupt the random key by the same # of bits."},
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
        case 1000:
            arguments->only_given = 1;
            break;
        case 'm':
            errno = 0;
            value = strtol(arg, &endptr, 10);

            if(((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                    || (errno && value == 0))) {
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
            if(arguments->mismatches < 0) {
                if(arguments->random) {
                    argp_error(state, "--mismatches must be set and non-negative when using --random.\n");
                }
                if(arguments->only_given) {
                    argp_error(state, "--mismatches must be set and non-negative when using --only-given.\n");
                }
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
/// \param benchmark If benchmark mode is set to a non-zero value, then continue even if found.
/// \return Returns a 1 if found or a 0 if not. Returns a -1 if an error has occurred.
int gmp_validator(const uint256_t *starting_perm, const uint256_t *last_perm, const unsigned char *key,
        size_t key_size, uuid_t userId, const unsigned char *auth_cipher, int benchmark) {
    int sum = 0;
    // Declaration
    unsigned char *corrupted_key;
    unsigned char cipher[BLOCK_SIZE];
    int found = 0;

    uint256_key_iter *iter;
    aes256_enc_key_scheduler *key_scheduler;

    // Memory allocation
    if((corrupted_key = malloc(sizeof(*corrupted_key) * key_size)) == NULL) {
        perror("Error");
        return -1;
    }

    if((key_scheduler = aes256_enc_key_scheduler_create()) == NULL) {
        perror("Error");
        free(corrupted_key);
        return -1;
    }

    // Allocation and initialization
    if((iter = uint256_key_iter_create(key, starting_perm, last_perm)) == NULL) {
        perror("Error");
        aes256_enc_key_scheduler_destroy(key_scheduler);
        free(corrupted_key);
        return -1;
    }

    int count = 0;
    // While we haven't reached the end of iteration
    while(!uint256_key_iter_end(iter)) {
        count++;
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
            fprint_hex(stdout, corrupted_key, key_size);
            printf("\n");
        }

        // remove this comment block to enable early exit on valid key found
        // count is a tuning knob for how often the MPI collective should check
        // if the right key has been found.
        if(count == 10000) {
            MPI_Allreduce(&found, &sum, 1, MPI_INT, MPI_SUM, MPI_COMM_WORLD);

            if(sum == 1 && !benchmark) {
                break;
            }

            // not found yet, we'll check back after count is reached again
            count = 0;
        }
        uint256_key_iter_next(iter);
    }

    // Cleanup
    uint256_key_iter_destroy(iter);
    aes256_enc_key_scheduler_destroy(key_scheduler);
    free(corrupted_key);

    return found;
}

/// MPI implementation
/// \return Returns a 0 on successfully finding a match, a 1 when unable to find a match,
/// and a 2 when a general error has occurred.
int main(int argc, char *argv[]) {
    int my_rank, nprocs;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nprocs);
    MPI_Status status;
    MPI_Request request = MPI_REQUEST_NULL;

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

    int found, subfound;
    uint256_t starting_perm, ending_perm;
    struct timespec startTime, endTime;

    // Memory allocation
    if((key = malloc(sizeof(*key) * KEY_SIZE)) == NULL) {
        perror("ERROR");

        MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
    }

    if((corrupted_key = malloc(sizeof(*corrupted_key) * KEY_SIZE)) == NULL) {
        perror("ERROR");
        free(key);

        MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
    }

    if((key_scheduler = aes256_enc_key_scheduler_create()) == NULL) {
        perror("ERROR");
        free(corrupted_key);
        free(key);

        MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
    }

    if(my_rank == 0) {
        memset(&arguments, 0, sizeof(arguments));
        arguments.cipher_hex = NULL;
        arguments.key_hex = NULL;
        arguments.uuid_hex = NULL;
        // Default to -1 for no mismatches provided, aka. go through all mismatches.
        arguments.mismatches = -1;

        // Parse arguments
        argp_parse(&argp, argc, argv, 0, 0, &arguments);

        // Initialize values
        // Set the gmp prng algorithm and set a seed based on the current time
        gmp_randinit_default(randstate);
        gmp_randseed_ui(randstate, (unsigned long)time(NULL));

        mismatch = 0;
        ending_mismatch = KEY_SIZE * 8;

        // If --only-given option was set, set the validation range to only use the --mismatches value.
        if (arguments.only_given >= 0) {
            mismatch = arguments.mismatches;
            ending_mismatch = arguments.mismatches;
        }
        // If --mismatches is set and non-negative, set the ending_mismatch to its value.
        else if(arguments.mismatches >= 0) {
            ending_mismatch = arguments.mismatches;
        }

        if(arguments.random) {
            fprintf(stderr, "WARNING: Random mode set. All three arguments will be ignored and randomly"
                            " generated ones will be used in their place.\n");

            uuid_generate(userId);

            get_random_key(key, KEY_SIZE, randstate);
            get_random_corrupted_key(corrupted_key, key, arguments.mismatches, KEY_SIZE, randstate);

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
                    return ERROR_CODE_FAILURE;
                case 2:
                    fprintf(stderr, "ERROR: CIPHER did not have even length.\n");
                    return ERROR_CODE_FAILURE;
                default:
                    break;
            }

            switch(parse_hex(key, arguments.key_hex)) {
                case 1:
                    fprintf(stderr, "ERROR: KEY had non-hexadecimal characters.\n");
                    return ERROR_CODE_FAILURE;
                case 2:
                    fprintf(stderr, "ERROR: KEY did not have even length.\n");
                    return ERROR_CODE_FAILURE;
                default:
                    break;
            }

            if (uuid_parse(arguments.uuid_hex, userId) < 0) {
                fprintf(stderr, "ERROR: UUID not in canonical form.\n");
                return ERROR_CODE_FAILURE;
            }
        }
    }

    // Broadcast all of the relevant variable to every rank
    MPI_Bcast(&(arguments.verbose), 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&(arguments.benchmark), 1, MPI_INT, 0, MPI_COMM_WORLD);

    MPI_Bcast(auth_cipher, sizeof(uuid_t), MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(key, KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(corrupted_key, KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(userId, sizeof(userId), MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    MPI_Bcast(&mismatch, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&ending_mismatch, 1, MPI_INT, 0, MPI_COMM_WORLD);

    if (my_rank == 0) {
        if(arguments.verbose) {
            // Convert the uuid to a string for printing
            uuid_unparse(userId, uuid_str);

            fprintf(stderr, "INFO: Using UUID:                                 %s\n", uuid_str);

            fprintf(stderr, "INFO: Using AES-256 Key:                          ");
            fprint_hex(stderr, key, KEY_SIZE);
            fprintf(stderr, "\n");

            if(arguments.random) {
                fprintf(stderr, "INFO: Using AES-256 Corrupted Key (%d mismatches): ", arguments.mismatches);
                fprint_hex(stderr, corrupted_key, KEY_SIZE);
                fprintf(stderr, "\n");
            }

            fprintf(stderr, "INFO: AES-256 Authentication Cipher:              ");
            fprint_hex(stderr, auth_cipher, BLOCK_SIZE);
            fprintf(stderr, "\n");
        }

        // Initialize time for root rank
        clock_gettime(CLOCK_MONOTONIC, &startTime);
    }

    found = 0;

    for (; mismatch <= ending_mismatch && !found; mismatch++) {
        if(arguments.verbose && my_rank == 0) {
            fprintf(stderr, "INFO: Checking a hamming distance of %d...\n", mismatch);
        }

        uint256_get_perm_pair(&starting_perm, &ending_perm, (size_t)my_rank, (size_t)nprocs, mismatch, KEY_SIZE);
        subfound = gmp_validator(&starting_perm, &ending_perm, key, KEY_SIZE, userId, auth_cipher,
                arguments.benchmark);
        if (subfound < 0) {
            // Cleanup
            free(corrupted_key);
            free(key);

            MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
        }

        // Reduce all the "found" answers to a single found statement.
        // Also works as a natural barrier to make sure all processes are done validating before ending time.
        MPI_Allreduce(&subfound, &found, 1, MPI_INT, MPI_SUM, MPI_COMM_WORLD);
    }

    if(my_rank == 0) {
        clock_gettime(CLOCK_MONOTONIC, &endTime);
        double duration = difftime(endTime.tv_sec, startTime.tv_sec) + ((endTime.tv_nsec - startTime.tv_nsec) / 1e9);

        if(arguments.verbose) {
            fprintf(stderr, "INFO: Clock time: %f s\n", duration);
            fprintf(stderr, "INFO: Found: %d\n", found);
        }
    }

    // Cleanup
    aes256_enc_key_scheduler_destroy(key_scheduler);
    free(corrupted_key);
    free(key);

    MPI_Finalize();

    if(my_rank == 0) {
        return found ? ERROR_CODE_FOUND : ERROR_CODE_NOT_FOUND;
    }
    else {
        return ERROR_CODE_FOUND;
    }
}
