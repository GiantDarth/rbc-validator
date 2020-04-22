//
// Created by cp723 on 2/7/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <mpi.h>

#include <uuid/uuid.h>
#include <gmp.h>
#include <unistd.h>
#include <argp.h>
#include <pthread.h>

#include "iter/uint256_key_iter.h"
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

static char args_doc[] = "UUID KEY CIPHER\n-r/--random -m/--000=value";
static char prog_desc[] = "Given an AES-256 KEY and a CIPHER from an unreliable source,"
                          " progressively corrupt it by a certain number of bits until"
                          " a matching corrupted key is found. The matching key will be"
                          " sent to stdout.\n\nThis implementation uses MPI.\v"

                          "If the key is found then the program will have an exit code"
                          " 0. If not found, e.g. when providing --mismatches and"
                          " especially --exact, then the program will have an exit code"
                          " 1. For any general error, such as parsing, out-of-memory,"
                          " etc., the program will have an exit code 2.\n\n"

                          "The UUID, passed in canonical form, is the message that both"
                          " sources encrypt and is previously agreed upon.\n\n"

                          "The original KEY, passed in as hexadecimal, is corrupted by"
                          " a certain number of bits and compared against CIPHER. Only"
                          " AES-256 keys are currently supported.\n\n"

                          "The CIPHER, passed in as hexadecimal, is assumed to have been"
                          " generated in ECB mode, meaning given a 128-bit UUID, this"
                          " should be 128-bits long as well.";

struct arguments {
    int verbose, benchmark, random, fixed, count, all;
    char *cipher_hex, *key_hex, *uuid_hex;
    int mismatches, subkey_length;
};

static struct argp_option options[] = {
    {"all", 'a', 0, 0, "Don't cut out early when key is found."},
    {"mismatches", 'm', "value", 0, "The largest # of bits of corruption to test against,"
                                    " inclusively. Defaults to -1. If negative, then the"
                                    " size of key in bits will be the limit. If in random"
                                    " or benchmark mode, then this will also be used to"
                                    " corrupt the random key by the same # of bits; for"
                                    " this reason, it must be set and non-negative when"
                                    " in random or benchmark mode."},
    {"subkey", 's', "value", 0, "How many of the first bits to corrupt and iterate over."
                                " Must be between 1 and 256 bits. Defaults to 256."},
    {"count", 'c', 0, 0, "Count the number of keys tested and show it as verbose output."},
    {"fixed", 'f', 0, 0, "Only test the given mismatch, instead of progressing from 0 to"
                         " --mismatches. This is only valid when --mismatches is set and"
                         " non-negative."},
    {"random", 'r', 0, 0, "Instead of using arguments, randomly generate CIPHER, KEY, and"
                          " UUID. This must be accompanied by --mismatches, since it is used to"
                          " corrupt the random key by the same # of bits. --random and"
                          " --benchmark cannot be used together."},
    {"benchmark", 'b', 0, 0, "Instead of using arguments, strategically generate CIPHER, KEY, and"
                             " UUID. Specifically, generates a corrupted key that's always 50% of"
                             " way through a rank's workload, but randomly chooses the rank."
                             " --random and --benchmark cannot be used together."},
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
        case 'c':
            arguments->count = 1;
            break;
        case 'r':
            arguments->random = 1;
            break;
        case 'b':
            arguments->benchmark = 1;
            break;
        case 'f':
            arguments->fixed = 1;
            break;
        case 'a':
            arguments->all = 1;
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
        case 's':
            errno = 0;
            value = strtol(arg, &endptr, 10);

            if((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
               || (errno && value == 0)) {
                argp_failure(state, ERROR_CODE_FAILURE, errno, "--subkey");
            }

            if(*endptr != '\0') {
                argp_error(state, "--subkey contains invalid characters.\n");
            }

            if (value > KEY_SIZE * 8) {
                argp_error(state, "--subkey cannot exceed the key size for AES-256 in bits.\n");
            }
            else if (value < 1) {
                argp_error(state, "--subkey must be at least 1.\n");
            }

            arguments->subkey_length = (int)value;

            break;
        case ARGP_KEY_ARG:
            switch(state->arg_num) {
                case 0:
                    if(strlen(arg) != 36) {
                        argp_error(state, "UUID not 36 characters long.\n");
                    }
                    arguments->uuid_hex = arg;
                    break;
                case 1:
                    if(strlen(arg) != KEY_SIZE * 2) {
                        argp_error(state, "Only AES-256 keys supported. KEY not"
                                          " equivalent to 256-bits long.\n");
                    }
                    arguments->key_hex = arg;
                    break;
                case 2:
                    if(strlen(arg) != BLOCK_SIZE * 2) {
                        argp_error(state, "CIPHER not equivalent to 128-bits long.\n");
                    }
                    arguments->cipher_hex = arg;
                    break;
                default:
                    argp_usage(state);
            }
            break;
        case ARGP_KEY_NO_ARGS:
            if(!arguments->random && !arguments->benchmark) {
                argp_usage(state);
            }
            break;
        case ARGP_KEY_END:
            if(arguments->mismatches < 0) {
                if(arguments->random) {
                    argp_error(state, "--mismatches must be set and non-negative when using --random."
                                      "\n");
                }
                if(arguments->benchmark) {
                    argp_error(state, "--mismatches must be set and non-negative when using --benchmark."
                                      "\n");
                }
                if(arguments->fixed) {
                    argp_error(state, "--mismatches must be set and non-negative when using --fixed.\n");
                }
            }

            if(arguments->random && arguments->benchmark) {
                argp_error(state, "--random and --benchmark cannot be both set simultaneously.\n");
            }

            if(arguments->mismatches > arguments->subkey_length) {
                argp_error(state, "--mismatches cannot be set larger than --subkey.\n");
            }

            break;
        case ARGP_KEY_INIT:
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

/// Given a starting permutation, iterate forward through every possible permutation until one that's
/// matching last_perm is found, or until a matching cipher is found.
/// \param corrupted_key An allocated corrupted key to fill if the corrupted key was found. Must be at
/// least key_size bytes big.
/// \param starting_perm The permutation to start iterating from.
/// \param last_perm The final permutation to stop iterating at, inclusively.
/// \param key The original AES key.
/// \param userId A uuid_t that's used to as the message to encrypt.
/// \param auth_cipher The authentication cipher to test against
/// \param all If all mode is set to a non-zero value, then continue even if found.
/// \param validated_keys A counter to keep track of how many keys were traversed. If NULL, then this is
/// skipped.
/// \param verbose If set to non-zero, print verbose information to stderr.
/// \return Returns a 1 if found or a 0 if not. Returns a -1 if an error has occurred.
int gmp_validator(unsigned char *corrupted_key, const uint256_t *starting_perm,
        const uint256_t *last_perm, const unsigned char *key, uuid_t userId,
        const unsigned char *auth_cipher, int all, long long int *validated_keys, int verbose, int my_rank,
        int nprocs, int *global_found) {
    // Declaration
    unsigned char cipher[BLOCK_SIZE];
    int status = 0;
    int probe_flag = 0;
    long long int iter_count = 0;

    uint256_key_iter *iter;
    aes256_enc_key_scheduler *key_scheduler;

    MPI_Request *requests;
    MPI_Status *statuses;

    // Memory allocation
    if((key_scheduler = aes256_enc_key_scheduler_create()) == NULL) {
        perror("Error");

        return -1;
    }

    // Allocation and initialization
    if((iter = uint256_key_iter_create(key, starting_perm, last_perm)) == NULL) {
        perror("Error");

        aes256_enc_key_scheduler_destroy(key_scheduler);

        return -1;
    }

    if((requests = malloc(sizeof(MPI_Request) * nprocs)) == NULL) {
        perror("Error");

        uint256_key_iter_destroy(iter);
        aes256_enc_key_scheduler_destroy(key_scheduler);

        return -1;
    }

    if((statuses = malloc(sizeof(MPI_Status) * nprocs)) == NULL) {
        perror("Error");

        free(requests);

        uint256_key_iter_destroy(iter);
        aes256_enc_key_scheduler_destroy(key_scheduler);

        return -1;
    }

    // While we haven't reached the end of iteration
    while(!uint256_key_iter_end(iter) && (all || !(*global_found))) {
        ++iter_count;

        if(validated_keys != NULL) {
            ++(*validated_keys);
        }
        uint256_key_iter_get(iter, corrupted_key);
        aes256_enc_key_scheduler_update(key_scheduler, corrupted_key);

        // If encryption fails for some reason, break prematurely.
        if(aes256_ecb_encrypt(cipher, key_scheduler, userId, sizeof(uuid_t))) {
            status = -1;
            break;
        }

        // If the new cipher is the same as the passed in auth_cipher, set found to true and break
        if(memcmp(cipher, auth_cipher, sizeof(uuid_t)) == 0) {
            *global_found = 1;
            status = 1;

            if(verbose) {
                fprintf(stderr, "INFO: Found by rank: %d, alerting ranks ...\n", my_rank);
            }

            // alert all ranks that the key was found, including yourself
            for (int i = 0; i < nprocs; i++) {
                if(i != my_rank) {
                    MPI_Isend(global_found, 1, MPI_INT, i, 0, MPI_COMM_WORLD,
                            &(requests[i]));
                }
            }

            for (int i = 0; i < nprocs; i++) {
                if(i != my_rank) {
                    MPI_Wait(&(requests[i]), MPI_STATUS_IGNORE);
                }
            }
        }

        // this while loop avoids the busy wait caused by the mpi_recv
        // we probe for a message, once found, move on and actually receive the message
        if (!(*global_found) && iter_count % 128 == 0) {
            MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &probe_flag, MPI_STATUS_IGNORE);

            if(probe_flag) {
                MPI_Recv(global_found, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD,
                        MPI_STATUS_IGNORE);
            }
        }

        uint256_key_iter_next(iter);
    }

    // Cleanup
    free(statuses);
    free(requests);

    uint256_key_iter_destroy(iter);
    aes256_enc_key_scheduler_destroy(key_scheduler);

    return status;
}

/// MPI implementation
/// \return Returns a 0 on successfully finding a match, a 1 when unable to find a match,
/// and a 2 when a general error has occurred.
int main(int argc, char *argv[]) {
    int my_rank, nprocs;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nprocs);

    struct arguments arguments = { 0 };
    static struct argp argp = {options, parse_opt, args_doc, prog_desc};

    int global_found = 0;
    int subfound = 0;

    gmp_randstate_t randstate;

    uuid_t userId;
    char uuid_str[37];

    unsigned char *key;
    unsigned char *corrupted_key;
    unsigned char auth_cipher[BLOCK_SIZE];

    aes256_enc_key_scheduler *key_scheduler;

    int mismatch = 0;
    int ending_mismatch = KEY_SIZE * 8;

    uint256_t starting_perm, ending_perm;
    size_t max_count;
    mpz_t key_count;
    double start_time, duration, key_rate;
    long long int validated_keys = 0;

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

    mpz_init(key_count);

    // Default to -1 for no mismatches provided, aka. go through all mismatches.
    arguments.mismatches = -1;
    arguments.subkey_length = KEY_SIZE * 8;

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    // If --fixed option was set, set the validation range to only use the --mismatches value.
    if (arguments.fixed) {
        mismatch = arguments.mismatches;
        ending_mismatch = arguments.mismatches;
    }
    // If --mismatches is set and non-negative, set the ending_mismatch to its value.
    else if (arguments.mismatches >= 0) {
        ending_mismatch = arguments.mismatches;
    }

    if (arguments.random || arguments.benchmark) {
        if (my_rank == 0) {
            // Initialize values
            // Set the gmp prng algorithm and set a seed based on the current time
            gmp_randinit_default(randstate);
            gmp_randseed_ui(randstate, (unsigned long) time(NULL));

            if (arguments.random) {
                fprintf(stderr, "WARNING: Random mode set. All three arguments will be ignored"
                                " and randomly generated ones will be used in their place.\n");
            }
            else if (arguments.benchmark) {
                fprintf(stderr, "WARNING: Benchmark mode set. All three arguments will be ignored"
                                " and randomly generated ones will be used in their place.\n");
            }

            uuid_generate(userId);

            get_random_key(key, KEY_SIZE, randstate);
            get_random_corrupted_key(corrupted_key, key, arguments.mismatches, KEY_SIZE,
                                     arguments.subkey_length, randstate, arguments.benchmark, nprocs);

            aes256_enc_key_scheduler_update(key_scheduler, corrupted_key);
            if (aes256_ecb_encrypt(auth_cipher, key_scheduler, userId, sizeof(uuid_t))) {
                // Cleanup
                mpz_clear(key_count);
                aes256_enc_key_scheduler_destroy(key_scheduler);
                free(corrupted_key);
                free(key);

                return ERROR_CODE_FAILURE;
            }
        }

        // Broadcast all of the relevant variable to every rank
        MPI_Bcast(auth_cipher, sizeof(uuid_t), MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        MPI_Bcast(key, KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        MPI_Bcast(corrupted_key, KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        MPI_Bcast(userId, sizeof(userId), MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    }
    else {
        switch (parse_hex(auth_cipher, arguments.cipher_hex)) {
            case 1:
                fprintf(stderr, "ERROR: CIPHER had non-hexadecimal characters.\n");
                return ERROR_CODE_FAILURE;
            case 2:
                fprintf(stderr, "ERROR: CIPHER did not have even length.\n");
                return ERROR_CODE_FAILURE;
            default:
                break;
        }

        switch (parse_hex(key, arguments.key_hex)) {
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

    if (my_rank == 0 && arguments.verbose) {
        // Convert the uuid to a string for printing
        uuid_unparse(userId, uuid_str);

        fprintf(stderr, "INFO: Using UUID:                                 %s\n", uuid_str);

        fprintf(stderr, "INFO: Using AES-256 Key:                          ");
        fprint_hex(stderr, key, KEY_SIZE);
        fprintf(stderr, "\n");

        if(arguments.random) {
            fprintf(stderr, "INFO: Using AES-256 Corrupted Key (%d mismatches): ",
                    arguments.mismatches);
            fprint_hex(stderr, corrupted_key, KEY_SIZE);
            fprintf(stderr, "\n");
        }

        fprintf(stderr, "INFO: AES-256 Authentication Cipher:              ");
        fprint_hex(stderr, auth_cipher, BLOCK_SIZE);
        fprintf(stderr, "\n");
    }

    // Initialize time for root rank
    start_time = MPI_Wtime();

    for (; mismatch <= ending_mismatch && !global_found; mismatch++) {
        if(my_rank == 0 && arguments.verbose) {
            fprintf(stderr, "INFO: Checking a hamming distance of %d...\n", mismatch);
        }

        mpz_bin_uiui(key_count, arguments.subkey_length, mismatch);

        // Only have this rank run if it's within range of possible keys
        if(mpz_cmp_ui(key_count, (unsigned long)my_rank) > 0) {
            max_count = nprocs;
            // Set the count of pairs to the range of possible keys if there are more ranks
            // than possible keys
            if(mpz_cmp_ui(key_count, nprocs) < 0) {
                max_count = mpz_get_ui(key_count);
            }

            uint256_get_perm_pair(&starting_perm, &ending_perm, (size_t)my_rank, max_count, mismatch,
                    KEY_SIZE, arguments.subkey_length);
            subfound = gmp_validator(corrupted_key, &starting_perm, &ending_perm, key, userId,
                    auth_cipher, arguments.all, arguments.count ? &validated_keys : NULL,
                    arguments.verbose, my_rank, max_count, &global_found);
            if (subfound < 0) {
                // Cleanup
                mpz_clears(key_count, validated_keys, NULL);
                aes256_enc_key_scheduler_destroy(key_scheduler);
                free(corrupted_key);
                free(key);

                MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
            }
        }
    }

    if(subfound == 0 && !global_found) {
        fprintf(stderr, "Rank %d Bleh\n", my_rank);
        MPI_Recv(&global_found, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    }

    duration = MPI_Wtime() - start_time;

    fprintf(stderr, "INFO Rank %d: Clock time: %f s\n", my_rank, duration);

    if(my_rank == 0) {
        MPI_Reduce(MPI_IN_PLACE, &duration, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);
    }
    else {
        MPI_Reduce(&duration, &duration, 1, MPI_DOUBLE, MPI_MAX, 0, MPI_COMM_WORLD);
    }

    if(my_rank == 0 && arguments.verbose) {
        fprintf(stderr, "INFO: Max Clock time: %f s\n", duration);
    }

    if(arguments.count) {
        if(my_rank == 0) {
            MPI_Reduce(MPI_IN_PLACE, &validated_keys, 1, MPI_LONG_LONG_INT, MPI_SUM, 0,
                    MPI_COMM_WORLD);

            // Divide validated_keys by duration
            key_rate = (double)validated_keys / duration;

            gmp_fprintf(stderr, "INFO: Keys searched: %lld\n", validated_keys);
            gmp_fprintf(stderr, "INFO: Keys per second: %.9g\n", key_rate);
        }
        else {
            MPI_Reduce(&validated_keys, &validated_keys, 1, MPI_LONG_LONG_INT, MPI_SUM, 0,
                    MPI_COMM_WORLD);
        }
    }

    if(subfound) {
        fprint_hex(stdout, corrupted_key, KEY_SIZE);
        printf("\n");
    }

    // Cleanup
    mpz_clear(key_count);
    aes256_enc_key_scheduler_destroy(key_scheduler);
    free(corrupted_key);
    free(key);

    MPI_Finalize();

//    if(my_rank == 0) {
//        return found ? ERROR_CODE_FOUND : ERROR_CODE_NOT_FOUND;
//    }
//    else {
//        return ERROR_CODE_FOUND;
//    }

    return 0;
}
