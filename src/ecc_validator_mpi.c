//
// Created by cp723 on 2/7/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
//#include <math.h>
#include <mpi.h>

#include <gmp.h>
#include <unistd.h>
#include <sys/wait.h>
#include <argp.h>
#include <pthread.h>

#include "iter/uint256_key_iter.h"
#include "util.h"
#include "../../micro-ecc/uECC.h"

#define ERROR_CODE_FOUND 0
#define ERROR_CODE_NOT_FOUND 1
#define ERROR_CODE_FAILURE 2

#define PRIV_KEY_SIZE 32
#define PUB_KEY_SIZE 64

int flags[2] = {0, -1};

struct comm_arguments {
    MPI_Request request;
};

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
    char *host_priv_key_hex, *client_pub_key_hex;
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
        const unsigned char *client_pub_key, int all, mpz_t *validated_keys, int verbose, int my_rank,
        int nprocs, MPI_Request request) {
    // Declaration
    int found = 0;
    const struct uECC_Curve_t * curve = uECC_secp256r1();
    unsigned char current_pub_key[PUB_KEY_SIZE];   // this is generated from corrupt_priv_key
    uint256_key_iter *iter;

    // Allocation and initialization
    if((iter = uint256_key_iter_create(host_priv_key, starting_perm, last_perm)) == NULL) {
        perror("Error");

        return -1;
    }

    // While we haven't reached the end of iteration
    while(!uint256_key_iter_end(iter)) {
        if(validated_keys != NULL) {
            mpz_add_ui(*validated_keys, *validated_keys, 1);
        }
        // get next current_priv_key
        uint256_key_iter_get(iter, corrupt_priv_key);

        // If the public key exists and if the new cipher is the same as the passed in
        // auth_cipher, set found to true and break
        if (uECC_compute_public_key(corrupt_priv_key, current_pub_key, curve) &&
                memcmp(current_pub_key, client_pub_key, PUB_KEY_SIZE) == 0) {
            printf("**gmp_validator found\n");
            flags[0] = 1;
            flags[1] = my_rank;
            found = 1;

            if(verbose) {
                fprintf(stderr, "INFO: Found by rank: %d, alerting ranks ...\n", my_rank);
            }

            // alert all ranks that the key was found, including yourself
            for (int i = 0; i < nprocs; i++) {
                MPI_Isend(&flags, 2, MPI_INT, i, 0, MPI_COMM_WORLD, &request);
                MPI_Wait(&request, MPI_STATUS_IGNORE);
            }
        }

        if(!all && flags[0]) {
            printf("rank: %d is breaking early\n", my_rank);
            break;
        }

        uint256_key_iter_next(iter);
    }

    // Cleanup
    uint256_key_iter_destroy(iter);

    return found;
}

void *comm_worker(void *arg) {
    int probe_flag = 0;

    struct comm_arguments *args = (struct comm_arguments*)arg;

    // this while loop avoids the busy wait caused by the mpi_recv
    // we probe for a message, once found, move on and actually receive the message
    while (!probe_flag) {
        MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &probe_flag, MPI_STATUS_IGNORE);

        usleep(1000);
    }

    MPI_Recv(&flags, 2, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
    MPI_Wait(&(args->request), MPI_STATUS_IGNORE);

    return 0;
}

/// MPI implementation
/// \return Returns a 0 on successfully finding a match, a 1 when unable to find a match,
/// and a 2 when a general error has occurred.
int main(int argc, char *argv[]) {
    int my_rank, nprocs, level;

    pthread_t comm_thread;

    MPI_Init_thread(&argc, &argv, MPI_THREAD_MULTIPLE, &level);
    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nprocs);

    struct arguments arguments;
    static struct argp argp = {options, parse_opt, args_doc, prog_desc};

    struct comm_arguments comm_args;

    gmp_randstate_t randstate;

    const struct uECC_Curve_t *curve = uECC_secp256r1();
    unsigned char *host_priv_key;
    unsigned char *client_pub_key;
    unsigned char *corrupt_priv_key;

    int mismatch, ending_mismatch;

    int subfound = 0;
    uint256_t starting_perm, ending_perm;
    size_t max_count;
    mpz_t key_count, validated_keys;
    double start_time, duration;

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

    mpz_inits(key_count, validated_keys, NULL);

    if(my_rank == 0) {
        memset(&arguments, 0, sizeof(arguments));
        arguments.host_priv_key_hex = NULL;
        arguments.client_pub_key_hex = NULL;
        // Default to -1 for no mismatches provided, aka. go through all mismatches.
        arguments.mismatches = -1;
        arguments.subkey_length = PRIV_KEY_SIZE * 8;

        // Parse arguments
        argp_parse(&argp, argc, argv, 0, 0, &arguments);

        // Initialize values
        // Set the gmp prng algorithm and set a seed based on the current time
        gmp_randinit_default(randstate);
        gmp_randseed_ui(randstate, (unsigned long)time(NULL));

        mismatch = 0;
        ending_mismatch = PUB_KEY_SIZE * 8;

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
            if(arguments.random) {
                fprintf(stderr, "WARNING: Random mode set. All three arguments will be ignored and"
                                " randomly generated ones will be used in their place.\n");
            }
            else if(arguments.benchmark) {
                fprintf(stderr, "WARNING: Benchmark mode set. All three arguments will be ignored and"
                                " randomly generated ones will be used in their place.\n");
            }

            get_random_key(host_priv_key, PRIV_KEY_SIZE, randstate);
            get_random_corrupted_key(corrupt_priv_key, host_priv_key, arguments.mismatches, PRIV_KEY_SIZE,
                    arguments.subkey_length, randstate, arguments.benchmark, nprocs);

            if (!uECC_compute_public_key(corrupt_priv_key, client_pub_key, curve)) {
                printf("ERROR host uECC_compute_public_key - abort run");
                free(host_priv_key);
                free(client_pub_key);
                free(corrupt_priv_key);

                return ERROR_CODE_FAILURE;
            }
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
    }

//    printf("%d - host_priv_key: ", my_rank);
//    fprint_hex(stdout, host_priv_key, PRIV_KEY_SIZE);
//    fprintf(stdout, "\n");


    // Broadcast all of the relevant variable to every rank
    MPI_Bcast(&(arguments.verbose), 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&(arguments.benchmark), 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&(arguments.subkey_length), 1, MPI_INT, 0, MPI_COMM_WORLD);

    MPI_Bcast(host_priv_key, PRIV_KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(corrupt_priv_key, PRIV_KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(client_pub_key, PUB_KEY_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    MPI_Bcast(&mismatch, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(&ending_mismatch, 1, MPI_INT, 0, MPI_COMM_WORLD);

//    printf("%d - host_priv_key: ", my_rank);
//    fprint_hex(stdout, host_priv_key, PRIV_KEY_SIZE);
//    fprintf(stdout, "\n");

    if (my_rank == 0) {
        if(arguments.verbose) {
            fprintf(stderr, "INFO: Using secp256r1 Host Private Key            : ");
            fprint_hex(stderr, host_priv_key, PRIV_KEY_SIZE);
            fprintf(stderr, "\n");

            if(arguments.random) {
                fprintf(stderr, "INFO: Using secp256r1 Corrupted Key (%d mismatches): ", arguments.mismatches);
                fprint_hex(stderr, corrupt_priv_key, PRIV_KEY_SIZE);
                fprintf(stderr, "\n");
            }

            fprintf(stderr, "INFO: Using secp256r1 Client Public Key:\n ");
            fprint_hex(stderr, client_pub_key, PUB_KEY_SIZE);
            fprintf(stderr, "\n");
        }

        //memset(corrupt_priv_key, 0, PRIV_KEY_SIZE);
        // Initialize time for root rank
        start_time = MPI_Wtime();
    }

    comm_args.request = MPI_REQUEST_NULL;

    if (pthread_create(&comm_thread, NULL, comm_worker, &comm_args)) {
        fprintf(stderr, "Error while creating comm thread\n");
        return ERROR_CODE_FAILURE;
    }

    for (; mismatch <= ending_mismatch && !(flags[0]); mismatch++) {
        if(arguments.verbose && my_rank == 0) {
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
                    PRIV_KEY_SIZE, arguments.subkey_length);
            subfound = gmp_validator(corrupt_priv_key, &starting_perm, &ending_perm, host_priv_key,
                    client_pub_key, arguments.all, arguments.count ? &validated_keys : NULL,
                    arguments.verbose, my_rank, max_count, comm_args.request);
            if (subfound < 0) {
                // Cleanup
                mpz_clears(key_count, validated_keys, NULL);
                free(corrupt_priv_key);
                free(client_pub_key);
                free(host_priv_key);

                MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
            }
        }
    }

    printf("%d wait join comm_thread\n", my_rank);
    pthread_join(comm_thread, NULL);
    printf("%d done join comm_thread\n", my_rank);

    if(my_rank == 0) {
        duration = MPI_Wtime() - start_time;

        if(arguments.verbose) {
            fprintf(stderr, "INFO: Clock time: %f s\n", duration);
        }

        if(arguments.count) {
            mpf_t duration_mpf, key_rate;

            mpf_inits(duration_mpf, key_rate, NULL);

            mpf_set_d(duration_mpf, duration);
            mpf_set_z(key_rate, validated_keys);

            // Divide validated_keys by duration
            mpf_div(key_rate, key_rate, duration_mpf);

            gmp_fprintf(stderr, "INFO: Keys searched: %Zu\n", validated_keys);
            gmp_fprintf(stderr, "INFO: Keys per second: %.9Fg\n", key_rate);

            mpf_clears(duration_mpf, key_rate, NULL);
        }
    }

    if(subfound) {
        fprint_hex(stdout, corrupt_priv_key, PRIV_KEY_SIZE);
        printf("\n");
    }

    // Cleanup
    mpz_clears(key_count, validated_keys, NULL);
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
