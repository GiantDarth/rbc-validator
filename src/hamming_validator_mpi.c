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
#include <sys/wait.h>
#include <argp.h>
#include <pthread.h>

#include "uint256_key_iter.h"
#include "aes256-ni.h"
#include "util.h"

#define ERROR_CODE_FOUND 0
#define ERROR_CODE_NOT_FOUND 1
#define ERROR_CODE_FAILURE 2

#define KEY_SIZE 32
#define BLOCK_SIZE 16

int flags[2] = {0, -1};
double validated_keys = 0;

struct comm_arguments {
    MPI_Request request;
};

const char *argp_program_version = "hamming_validator MPI 0.1.0";
const char *argp_program_bug_address = "<cp723@nau.edu, Chris.Coffey@nau.edu>";
error_t argp_err_exit_status = ERROR_CODE_FAILURE;

static char args_doc[] = "CIPHER KEY UUID\n-r/--random -m/--mismatches=value";
static char prog_desc[] = "Given an AES-256 KEY and a CIPHER from an unreliable source,"
                          " progressively corrupt it by a certain number of bits until"
                          " a matching corrupted key is found. The matching key will be"
                          " sent to stdout.\n\nThis implementation uses MPI.\v"

                          "If the key is found then the program will have an exit code"
                          " 0. If not found, e.g. when providing --mismatches and"
                          " especially --exact, then the program will have an exit code"
                          " 1. For any general error, such as parsing, out-of-memory,"
                          " etc., the program will have an exit code 2.\n\n"

                          "The CIPHER, passed in as hexadecimal, is assumed to have been"
                          " generated in ECB mode, meaning given a 128-bit UUID, this"
                          " should be 128-bits long as well.\n\n"

                          "The original KEY, passed in as hexadecimal, is corrupted by"
                          " a certain number of bits and compared against CIPHER. Only"
                          " AES-256 keys are currently supported.\n\n"

                          "The UUID, passed in canonical form, is the message that both"
                          " sources encrypt and is previously agreed upon.";

struct arguments {
    int verbose, benchmark, random, fixed;
    char *cipher_hex, *key_hex, *uuid_hex;
    int mismatches;
};

static struct argp_option options[] = {
    {"benchmark", 'b', 0, 0, "Don't cut out early when key is found."},
    {"mismatches", 'm', "value", 0, "The largest # of bits of corruption to test against,"
                                    " inclusively. Defaults to -1. If negative, then the"
                                    " size of key in bits will be the limit. If in random"
                                    " mode, then this will also be used to corrupt the"
                                    " random key by the same # of bits; for this reason, it"
                                    " must be set and non-negative when in random mode."},
    {"fixed", 'f', 0, 0, "Only test the given mismatch, instead of progressing from 0 to"
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
        case 'f':
            arguments->fixed = 1;
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
                if(arguments->fixed) {
                    argp_error(state, "--mismatches must be set and non-negative when using --fixed.\n");
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
/// \param corrupted_key An allocated corrupted key to fill if the corrupted key was found. Must be at least
/// key_size bytes big.
/// \param starting_perm The permutation to start iterating from.
/// \param last_perm The final permutation to stop iterating at, inclusively.
/// \param key The original AES key.
/// \param userId A uuid_t that's used to as the message to encrypt.
/// \param auth_cipher The authentication cipher to test against
/// \param benchmark If benchmark mode is set to a non-zero value, then continue even if found.
/// \return Returns a 1 if found or a 0 if not. Returns a -1 if an error has occurred.
int gmp_validator(unsigned char *corrupted_key, const uint256_t *starting_perm, const uint256_t *last_perm,
        const unsigned char *key, uuid_t userId, const unsigned char *auth_cipher, int benchmark, int verbose,
        int my_rank, int nprocs, MPI_Request request) {
    // Declaration
    unsigned char cipher[BLOCK_SIZE];
    int found = 0;

    uint256_key_iter *iter;
    aes256_enc_key_scheduler *key_scheduler;

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

//    int count = 0;
    // While we haven't reached the end of iteration
    while(!uint256_key_iter_end(iter)) {
//        count++;
        validated_keys++;
        uint256_key_iter_get(iter, corrupted_key);
        aes256_enc_key_scheduler_update(key_scheduler, corrupted_key);

        // If encryption fails for some reason, break prematurely.
        if(aes256_ecb_encrypt(cipher, key_scheduler, userId, sizeof(uuid_t))) {
            found = -1;
            break;
        }

        // If the new cipher is the same as the passed in auth_cipher, set found to true and break
        if(memcmp(cipher, auth_cipher, sizeof(uuid_t)) == 0) {
            flags[0] = 1;
            found = 1;
            if(verbose) {
                fprintf(stderr, "INFO: Found: %d\n", found);
            }
        }

        // remove this comment block to enable early exit on valid key found
        // count is a tuning knob for how often the MPI collective should check
        // if the right key has been found.
//        if(count == 10000) {
//            MPI_Allreduce(&found, &sum, 1, MPI_INT, MPI_SUM, MPI_COMM_WORLD);
//
//            if(sum == 1 && !benchmark) {
//                break;
//            }
//
//            // not found yet, we'll check back after count is reached again
//            count = 0;
//        }

        // need to send two ints because only want one rank to hit this code
        // one int is flag, other int is the rank that found it
        if (flags[0] == 1 && flags[1] == -1){
            flags[0] = 1;
            flags[1] = my_rank;
            if(verbose) {
                fprintf(stderr, "INFO: Found by rank: %d, alerting ranks ...\n", my_rank);
            }

            // alert all ranks that the key was found, including yourself
            for (int i = 0; i < nprocs; i++) {
                MPI_Isend(&flags, 2, MPI_INT, i, 0, MPI_COMM_WORLD, &request);
                MPI_Wait(&request, MPI_STATUS_IGNORE);
            }

            if(!benchmark) {
                break;
            }
        }

        // for all ranks that didn't find it first
        if (flags[0] == 1 && !benchmark) {
            //printf("rank: %d is breaking early\n", my_rank);
            break;
        }

        uint256_key_iter_next(iter);
    }

    // Cleanup
    uint256_key_iter_destroy(iter);
    aes256_enc_key_scheduler_destroy(key_scheduler);

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

    uuid_t userId;
    char uuid_str[37];

    unsigned char *key;
    unsigned char *corrupted_key;
    unsigned char auth_cipher[BLOCK_SIZE];

    aes256_enc_key_scheduler *key_scheduler;

    int mismatch, ending_mismatch;

    int subfound = 0;
    uint256_t starting_perm, ending_perm;
    size_t max_count;
    mpz_t key_count;
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

    mpz_init(key_count);

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

        // If --fixed option was set, set the validation range to only use the --mismatches value.
        if (arguments.fixed) {
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
            get_random_corrupted_key(corrupted_key, key, arguments.mismatches, KEY_SIZE, randstate, nprocs);

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

    comm_args.request = MPI_REQUEST_NULL;

    if (pthread_create(&comm_thread, NULL, comm_worker, &comm_args)) {
        fprintf(stderr, "Error while creating comm thread\n");
        return ERROR_CODE_FAILURE;
    }

    for (; mismatch <= ending_mismatch && !(flags[0]); mismatch++) {
        if(arguments.verbose && my_rank == 0) {
            fprintf(stderr, "INFO: Checking a hamming distance of %d...\n", mismatch);
        }

        mpz_bin_uiui(key_count, KEY_SIZE * 8, mismatch);

        // Only have this rank run if it's within range of possible keys
        if(mpz_cmp_ui(key_count, (unsigned long)my_rank) > 0) {
            max_count = nprocs;
            // Set the count of pairs to the range of possible keys if there are more ranks
            // than possible keys
            if(mpz_cmp_ui(key_count, nprocs) < 0) {
                max_count = mpz_get_ui(key_count);
            }

            uint256_get_perm_pair(&starting_perm, &ending_perm, (size_t)my_rank, max_count, mismatch, KEY_SIZE);
            subfound = gmp_validator(corrupted_key, &starting_perm, &ending_perm, key, userId, auth_cipher,
                                     arguments.benchmark, arguments.verbose, my_rank, max_count, comm_args.request);
            if (subfound < 0) {
                // Cleanup
                mpz_clear(key_count);
                aes256_enc_key_scheduler_destroy(key_scheduler);
                free(corrupted_key);
                free(key);

                MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
            }
        }
    }

    pthread_join(comm_thread, NULL);

    if(my_rank == 0) {
        clock_gettime(CLOCK_MONOTONIC, &endTime);
        double duration = difftime(endTime.tv_sec, startTime.tv_sec) + ((endTime.tv_nsec - startTime.tv_nsec) / 1e9);

        if(arguments.verbose) {
            fprintf(stderr, "INFO: Clock time: %f s\n", duration);
        }

        fprintf(stderr, "INFO: Keys searched: %f\n",validated_keys);
        fprintf(stderr, "INFO: Keys per second: %.17g\n",duration / validated_keys);
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
