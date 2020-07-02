//
// Created by cp723 on 2/7/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <mpi.h>

#include <gmp.h>
#include <argp.h>

#include "iter/uint256_key_iter.h"
#include "util.h"
#include "../lib/micro-ecc/uECC.h"

#define ERROR_CODE_FOUND 0
#define ERROR_CODE_NOT_FOUND 1
#define ERROR_CODE_FAILURE 2

#define PRIV_KEY_SIZE 32
#define PUB_KEY_SIZE 64

const char *argp_program_version = "ecc_validator MPI 0.1.0";
const char *argp_program_bug_address = "<Duane.Booher@nau.edu, cp723@nau.edu>";
error_t argp_err_exit_status = ERROR_CODE_FAILURE;

static char args_doc[] = "HOST_PRIV_KEY CLIENT_PUB_KEY\n-r/--random -m/--mismatches=value";
static char prog_desc[] = "Given an ECC secp256r1 and a HOST_PRIV_KEY (host private key)"
                          " and a CLIENT_PUB_KEY (client public key) from an unreliable"
                          " source, progressively corrupt the host private key by a"
                          " certain number of bits until a matching corrupted key is"
                          " found. The matching key will be sent to stdout."

                          "\n\nThis implementation uses MPI."

                          "\vIf the key is found then the program will have an exit code"
                          " 0. If not found, e.g. when providing --mismatches and"
                          " especially --exact, then the program will have an exit code"
                          " 1. For any general error, such as parsing, out-of-memory,"
                          " etc., the program will have an exit code 2."

                          "\n\nThe original HOST_PRIV_KEY (host private key), passed in as"
                          " hexadecimal, is corrupted by a certain number of bits. The"
                          " resulting new private key's public key is compared against"
                          " the CLIENT_PUB_KEY (client public key) which is also passed"
                          " in hexadecimal in uncompressed form."

                          "\n\nOnly ECC secp256r1 keys are currently supported.";

struct arguments {
    int verbose, benchmark, random, fixed, count, all;
    char *host_priv_key_hex, *client_pub_key_hex;
    int mismatches, subkey_length;
};

static struct argp_option options[] = {
    {"all", 'a', 0, 0, "Don't cut out early when key is found.", 0},
    {"mismatches", 'm', "value", 0, "The largest # of bits of corruption to test against,"
                                    " inclusively. Defaults to -1. If negative, then the"
                                    " size of key in bits will be the limit. If in random"
                                    " or benchmark mode, then this will also be used to"
                                    " corrupt the random key by the same # of bits; for"
                                    " this reason, it must be set and non-negative when"
                                    " in random or benchmark mode.", 0},
    {"subkey", 's', "value", 0, "How many of the first bits to corrupt and iterate over."
                                " Must be between 1 and 256 bits. Defaults to 256.", 0},
    {"count", 'c', 0, 0, "Count the number of keys tested and show it as verbose output.", 0},
    {"fixed", 'f', 0, 0, "Only test the given mismatch, instead of progressing from 0 to"
                         " --mismatches. This is only valid when --mismatches is set and"
                         " non-negative.", 0},
    {"random", 'r', 0, 0, "Instead of using arguments, randomly generate CIPHER, KEY, and"
                          " UUID. This must be accompanied by --mismatches, since it is used to"
                          " corrupt the random key by the same # of bits. --random and"
                          " --benchmark cannot be used together.", 0},
    {"benchmark", 'b', 0, 0, "Instead of using arguments, strategically generate CIPHER, KEY, and"
                             " UUID. Specifically, generates a corrupted key that's always 50% of"
                             " way through a rank's workload, but randomly chooses the rank."
                             " --random and --benchmark cannot be used together.", 0},
    {"verbose", 'v', 0, 0, "Produces verbose output and time taken to stderr.", 0},
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

            if (value > PRIV_KEY_SIZE * 8) {
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

            if (value > PRIV_KEY_SIZE * 8) {
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
                    if(strlen(arg) != PRIV_KEY_SIZE * 2) {
                        argp_error(state, "The HOST_PRIV_KEY (host private key) must be 32 bytes"
                                          " long for secp256r1.\n");
                    }
                    arguments->host_priv_key_hex = arg;
                    break;
                case 1:
                    if(strlen(arg) != PUB_KEY_SIZE * 2) {
                        argp_error(state, "The CLIENT_PUB_KEY (client public key) must be 64 bytes"
                                          " long for secp256r1.\n");
                    }
                    arguments->client_pub_key_hex = arg;
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
/// \param corrupt_priv_key An allocated corrupted key to fill if the corrupted key was found. Must be at
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
int gmp_validator(unsigned char *corrupt_priv_key, const uint256_t *starting_perm,
        const uint256_t *last_perm, const unsigned char *host_priv_key,
        const unsigned char *client_pub_key, int all, long long int *validated_keys, int verbose,
        int my_rank, int nprocs, int *global_found) {
    // Declaration
    int status = 0;
    int probe_flag = 0;
    long long int iter_count = 0;

    const struct uECC_Curve_t *curve = uECC_secp256r1();
    unsigned char current_pub_key[PUB_KEY_SIZE];   // this is generated from corrupt_priv_key
    uint256_key_iter *iter;

    MPI_Request *requests;
    MPI_Status *statuses;

    // Allocation and initialization
    if((iter = uint256_key_iter_create(host_priv_key, starting_perm, last_perm)) == NULL) {
        perror("Error");

        return -1;
    }

    if((requests = malloc(sizeof(MPI_Request) * nprocs)) == NULL) {
        perror("Error");

        uint256_key_iter_destroy(iter);

        return -1;
    }

    if((statuses = malloc(sizeof(MPI_Status) * nprocs)) == NULL) {
        perror("Error");

        free(requests);

        uint256_key_iter_destroy(iter);

        return -1;
    }

    // While we haven't reached the end of iteration
    while(!uint256_key_iter_end(iter) && (all || !(*global_found))) {
        ++iter_count;

        if(validated_keys != NULL) {
            ++(*validated_keys);
        }
        // get next current_priv_key
        uint256_key_iter_get(iter, corrupt_priv_key);

        // If the public key exists and if the new cipher is the same as the passed in
        // auth_cipher, set found to true and break
        if (uECC_compute_public_key(corrupt_priv_key, current_pub_key, curve) &&
                memcmp(current_pub_key, client_pub_key, PUB_KEY_SIZE) == 0) {
            *global_found = 1;
            status = 1;

            if(verbose) {
                fprintf(stderr, "INFO: Found by rank: %d, alerting ranks ...\n", my_rank);
            }

            if(!all) {
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
        }

        if (!all && !(*global_found) && iter_count % 128 == 0) {
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
    static struct argp argp = {options, parse_opt, args_doc, prog_desc, 0, 0, 0};

    int global_found = 0;
    int subfound = 0;

    gmp_randstate_t randstate;

    const struct uECC_Curve_t *curve = uECC_secp256r1();
    unsigned char *host_priv_key;
    unsigned char *client_pub_key;
    unsigned char *corrupt_priv_key;

    int mismatch = 0;
    int ending_mismatch = PRIV_KEY_SIZE * 8;

    uint256_t starting_perm, ending_perm;
    size_t max_count;
    mpz_t key_count;
    double start_time, duration, key_rate;
    long long int validated_keys = 0;

    // Memory allocation
    if((host_priv_key = malloc(sizeof(*host_priv_key) * PRIV_KEY_SIZE)) == NULL) {
        perror("ERROR");

        MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
    }

    if((client_pub_key = malloc(sizeof(*client_pub_key) * PUB_KEY_SIZE)) == NULL) {
        perror("ERROR");
        free(host_priv_key);

        MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
    }

    if((corrupt_priv_key = malloc(sizeof(*corrupt_priv_key) * PRIV_KEY_SIZE)) == NULL) {
        perror("ERROR");
        free(host_priv_key);
        free(client_pub_key);

        MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
    }

    mpz_init(key_count);

    memset(&arguments, 0, sizeof(arguments));

    arguments.host_priv_key_hex = NULL;
    arguments.client_pub_key_hex = NULL;
    // Default to -1 for no mismatches provided, aka. go through all mismatches.
    arguments.mismatches = -1;
    arguments.subkey_length = PRIV_KEY_SIZE * 8;

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    // If --fixed option was set, set the validation range to only use the --mismatches value.
    if (arguments.fixed) {
        mismatch = arguments.mismatches;
        ending_mismatch = arguments.mismatches;
    }
    // If --mismatches is set and non-negative, set the ending_mismatch to its value.
    else if(arguments.mismatches >= 0) {
        ending_mismatch = arguments.mismatches;
    }

    if(arguments.random || arguments.benchmark) {
        if(my_rank == 0) {
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

            get_random_key(host_priv_key, PRIV_KEY_SIZE, randstate);
            get_random_corrupted_key(corrupt_priv_key, host_priv_key, arguments.mismatches,
                                     arguments.subkey_length, randstate, arguments.benchmark, nprocs);

            if (!uECC_compute_public_key(corrupt_priv_key, client_pub_key, curve)) {
                printf("ERROR host uECC_compute_public_key - abort run");
                free(host_priv_key);
                free(client_pub_key);
                free(corrupt_priv_key);

                return ERROR_CODE_FAILURE;
            }
        }

        // Broadcast all of the relevant variable to every rank
        MPI_Bcast(host_priv_key, PRIV_KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        MPI_Bcast(corrupt_priv_key, PRIV_KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        MPI_Bcast(client_pub_key, PUB_KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    }
    else {
        switch(parse_hex(host_priv_key, arguments.host_priv_key_hex)) {
            case 1:
                fprintf(stderr, "ERROR: HOST_PRIV_KEY had non-hexadecimal characters.\n");
                return ERROR_CODE_FAILURE;
            case 2:
                fprintf(stderr, "ERROR: HOST_PRIV_KEY did not have even length.\n");
                return ERROR_CODE_FAILURE;
            default:
                break;
        }

        switch(parse_hex(client_pub_key, arguments.client_pub_key_hex)) {
            case 1:
                fprintf(stderr, "ERROR: CLIENT_PUB_KEY had non-hexadecimal characters.\n");
                return ERROR_CODE_FAILURE;
            case 2:
                fprintf(stderr, "ERROR: CLIENT_PUB_KEY did not have even length.\n");
                return ERROR_CODE_FAILURE;
            default:
                break;
        }
    }

    if (my_rank == 0 && arguments.verbose) {
        fprintf(stderr, "INFO: Using secp256r1 Host Private Key            : ");
        fprint_hex(stderr, host_priv_key, PRIV_KEY_SIZE);
        fprintf(stderr, "\n");

        if(arguments.random) {
            fprintf(stderr, "INFO: Using secp256r1 Corrupted Key (%d mismatches): ",
                    arguments.mismatches);
            fprint_hex(stderr, corrupt_priv_key, PRIV_KEY_SIZE);
            fprintf(stderr, "\n");
        }

        fprintf(stderr, "INFO: Using secp256r1 Client Public Key:\n ");
        fprint_hex(stderr, client_pub_key, PUB_KEY_SIZE);
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
                    arguments.subkey_length);
            subfound = gmp_validator(corrupt_priv_key, &starting_perm, &ending_perm, host_priv_key,
                    client_pub_key, arguments.all, arguments.count ? &validated_keys : NULL,
                    arguments.verbose, my_rank, max_count, &global_found);
            if (subfound < 0) {
                // Cleanup
                mpz_clear(key_count);
                free(corrupt_priv_key);
                free(client_pub_key);
                free(host_priv_key);

                MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
            }
        }
    }

    if(!(arguments.all) && subfound == 0 && !global_found) {
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

            fprintf(stderr, "INFO: Keys searched: %lld\n", validated_keys);
            fprintf(stderr, "INFO: Keys per second: %.9g\n", key_rate);
        }
        else {
            MPI_Reduce(&validated_keys, &validated_keys, 1, MPI_LONG_LONG_INT, MPI_SUM, 0,
                       MPI_COMM_WORLD);
        }
    }

    if(subfound) {
        fprint_hex(stdout, corrupt_priv_key, PRIV_KEY_SIZE);
        printf("\n");
    }

    // Cleanup
    mpz_clear(key_count);
    //aes256_enc_key_scheduler_destroy(key_scheduler);
    free(corrupt_priv_key);
    free(client_pub_key);
    free(host_priv_key);

    MPI_Finalize();

//    if(my_rank == 0) {
//        return found ? ERROR_CODE_FOUND : ERROR_CODE_NOT_FOUND;
//    }
//    else {
//        return ERROR_CODE_FOUND;
//    }

    return 0;
}
