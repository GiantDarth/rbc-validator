//
// Created by cp723 on 2/7/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/err.h>
#include <uuid/uuid.h>
#include <argp.h>

#if defined(USE_MPI)
#include <mpi.h>
#else
#include <omp.h>
#endif

#include "iter/uint256_key_iter.h"
#include "util.h"

#include "crypto/aes256-ni_enc.h"
#include "crypto/ec.h"

#define ERROR_CODE_FOUND 0
#define ERROR_CODE_NOT_FOUND 1
#define ERROR_CODE_FAILURE 2

#define SEED_SIZE 32

// If using OpenMP, and using Clang 10+ or GCC 9+, support omp_pause_resource_all
#if !defined(USE_MPI) && ((defined(__clang__) && __clang_major__ >= 10) || (!defined(__clang) && \
    __GNUC__ >= 9))
#define OMP_DESTROY_SUPPORT
#endif

// By setting it to 0, we're assuming it'll be zeroified when arguments are first created
#define MODE_NULL 0
#define MODE_AES 1
#define MODE_ECC 2

#ifdef USE_MPI
const char *argp_program_version = "aes_validator MPI 0.1.0";
#else
const char *argp_program_version = "rbc_validator OpenMP 0.1.0";
#endif
const char *argp_program_bug_address = "<cp723@nau.edu>";
error_t argp_err_exit_status = ERROR_CODE_FAILURE;

static char args_doc[] = "--mode=aes HOST_SEED CLIENT_CIPHER UUID\n"
                         "--mode=ecc HOST_SEED CLIENT_PUB_KEY\n"
                         "--mode=* -r/--random -m/--mismatches=value";
static char prog_desc[] = "Given an HOST_SEED and either:\n"
                          "1) a AES256 CLIENT_CIPHER and plaintext UUID;"
                          "2) a ECC Secp256r1 CLIENT_PUB_KEY;"
                          " where CLIENT_* is from an unreliable source."
                          " Progressively corrupt the chosen crytographic function by a certain"
                          " number of bits until a matching client seed is found. The matching"
                          " HOST_* will be sent to stdout, depending on the cryptographic function."

#ifdef USE_MPI
                          "\n\nThis implementation uses MPI."
#else
                          "\n\nThis implementation uses OpenMP."
#endif

                          "\vIf the client seed is found then the program will have an exit code"
                          " 0. If not found, e.g. when providing --mismatches and"
                          " especially --exact, then the program will have an exit code"
                          " 1. For any general error, such as parsing, out-of-memory,"
                          " etc., the program will have an exit code 2."

                          "\n\nThe original HOST_SEED, passed in as hexadecimal, is corrupted by"
                          " a certain number of bits and used to generate the cryptographic output."
                          " HOST_SEED is always 32 bytes, which corresponds to 64 hexadecimal"
                          " characters. If the cryptographic function requires more bytes, more will be"
                          " generated from HOST_SEED using SHAKE256."

                          "\n\nAES: Only AES-256-ECB is supported."

                          "\n\nThe CLIENT_CIPHER, passed in as hexadecimal, is assumed to have been"
                          " generated in ECB mode, meaning given a 128-bit UUID, this"
                          " should be 128-bits long as well (32 hexadecimal characters)."

                          "\n\nThe UUID, passed in canonical form,"
                          " is the message that both sources encrypt and is previously agreed upon."

                          "\n\nECC: Only ECC secp256r1 keys are currently supported."

                          "\n\nThe resulting private key derived from corrupting HOST_SEED"
                          " produces a new public key that is compared against"
                          " the CLIENT_PUB_KEY (client public key) which is also passed"
                          " in hexadecimal in uncompressed form (64 bytes, 128 hexadecimal"
                          " characters).";

struct arguments {
    int mode, verbose, benchmark, random, fixed, count, all;
    char *seed_hex, *client_crypto_hex, *uuid_hex;
    int mismatches, subkey_length;
#ifndef USE_MPI
    int threads;
#endif
};

static struct argp_option options[] = {
    {
        "mode",
        // Use the non-printable ASCII character '\5' to always enforce long mode (--mode)
        '\5',
        "[aes,ecc]",
        0,
        "REQUIRED. Choose between AES256 (aes) and ECC Secp256r1 (ecc).",
        0},
    {"all", 'a', 0, 0, "Don't cut out early when key is found.", 0},
    {
        "mismatches",
        'm',
        "value",
        0,
        "The largest # of bits of corruption to test against, inclusively. Defaults to -1. If"
        " negative, then the size of key in bits will be the limit. If in random or benchmark mode,"
        " then this will also be used to corrupt the random key by the same # of bits; for this"
        " reason, it must be set and non-negative when in random or benchmark mode. Cannot be larger"
        " than what --subkey-size is set to.",
        0},
    {
        "subkey",
        's',
        "value",
        0,
        "How many of the first bits to corrupt and iterate over. Must be between 1 and 256"
        " bits. Defaults to 256.",
        0},
    {
        "count",
        'c',
        0,
        0,
        "Count the number of keys tested and show it as verbose output.",
        0},
    {
        "fixed",
        'f',
        0,
        0,
        "Only test the given mismatch, instead of progressing from 0 to --mismatches. This is"
        " only valid when --mismatches is set and non-negative.",
        0},
    {
        "random",
        'r',
        0,
        0,
        "Instead of using arguments, randomly generate CIPHER, KEY, and UUID. This must be"
        " accompanied by --mismatches, since it is used to corrupt the random key by the same # of"
        " bits. --random and --benchmark cannot be used together.",
        0},
    {
        "benchmark",
        'b',
        0,
        0,
        "Instead of using arguments, strategically generate CIPHER, KEY, and UUID."
        " Specifically, generates a corrupted key that's always 50% of way through a rank's"
        " workload, but randomly chooses the thread. --random and --benchmark cannot be used"
        " together.",
        0},
    {
        "verbose",
        'v',
        0,
        0,
        "Produces verbose output and time taken to stderr.",
        0},
#ifndef USE_MPI
    {
        "threads",
        't',
        "count",
        0,
        "How many worker threads to use. Defaults to 0. If set to 0, then the number of"
        " threads used will be detected by the system.",
     0},
#endif
    { 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    // Used for strtol
    char *endptr;
    long value;

    switch(key) {
        case '\5':
            if(!strncmp(arg, "aes", 3)) {
                arguments->mode = MODE_AES;
            }
            else if(!strncmp(arg, "ecc", 3)) {
                arguments->mode = MODE_ECC;
            }
            else {
                argp_error(state, "--mode is invalid.\n");
            }
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

            if((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN))
                    || (errno && value == 0)) {
                argp_failure(state, ERROR_CODE_FAILURE, errno, "--mismatches");
            }

            if(*endptr != '\0') {
                argp_error(state, "--mismatches contains invalid characters.\n");
            }

            if (value > SEED_SIZE * 8) {
                fprintf(stderr, "--mismatches cannot exceed the seed size of 256-bits.\n");
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

            if (value > SEED_SIZE * 8) {
                argp_error(state, "--subkey cannot exceed the seed size of 256-bits.\n");
            }
            else if (value < 1) {
                argp_error(state, "--subkey must be at least 1.\n");
            }

            arguments->subkey_length = (int)value;

            break;
#ifndef USE_MPI
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
#endif
        case ARGP_KEY_ARG:
            switch(state->arg_num) {
                case 0:
                    if(strlen(arg) != SEED_SIZE * 2) {
                        argp_error(state, "HOST_SEED must be 256-bits long.\n");
                    }
                    arguments->seed_hex = arg;
                    break;
                case 1:
                    if(arguments->mode == MODE_AES) {
                        if(strlen(arg) != AES_BLOCK_SIZE * 2) {
                            argp_error(state, "CIPHER not equivalent to 128-bits long.\n");
                        }
                    }
                    arguments->client_crypto_hex = arg;
                    break;
                case 2:
                    if(arguments->mode == MODE_AES) {
                        if(strlen(arg) != 36) {
                            argp_error(state, "UUID not 36 characters long.\n");
                        }
                        arguments->uuid_hex = arg;
                    }
                    else {
                        argp_usage(state);
                    }
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
            if(arguments->mode == MODE_NULL) {
                argp_error(state, "--mode is required!\n");
            }

            if(!(arguments->random) && !(arguments->benchmark)) {
                // We don't need to check seed_hex since the first argument will always be set to it
                // and NO_ARGS is checked above
                if(arguments->client_crypto_hex == NULL) {
                    argp_usage(state);
                }

                if(arguments->mode == MODE_AES && arguments->uuid_hex == NULL) {
                    argp_usage(state);
                }
            }
            // No argument should be set if in random or benchmark mode
            else if(arguments->seed_hex != NULL) {
                argp_usage(state);
            }

            if(arguments->random && arguments->benchmark) {
                argp_error(state, "--random and --benchmark cannot be both set"
                                  " simultaneously.\n");
            }

            if(arguments->mismatches < 0) {
                if(arguments->random) {
                    argp_error(state,"--mismatches must be set and non-negative when using"
                                     "--random.\n");
                }
                if(arguments->benchmark) {
                    argp_error(state, "--mismatches must be set and non-negative when using"
                                      "--benchmark.\n");
                }
                if(arguments->fixed) {
                    argp_error(state, "--mismatches must be set and non-negative when using"
                                      " --fixed.\n");
                }
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
/// \param client_key An allocated corrupted host_seed to fill if the corrupted host_seed was found.
/// Must be at least 32 bytes big.
/// \param host_seed The original AES host_seed.
/// \param client_cipher The client cipher (16 bytes) to test against.
/// \param userId A uuid_t that's used as the plaintext to encrypt.
/// \param starting_perm The permutation to start iterating from.
/// \param last_perm The final permutation to stop iterating at, inclusively.
/// \param signal A pointer to a shared value. Used to signal the function to prematurely leave.
/// \param all If benchmark mode is set to a non-zero value, then continue even if found.
/// \param validated_keys A counter to keep track of how many keys were traversed. If NULL, then this
/// is skipped.
/// \return Returns a 1 if found or a 0 if not. Returns a -1 if an error has occurred.
int aes_validator(unsigned char *client_key, const unsigned char *host_seed,
                  const unsigned char *client_cipher, uuid_t userId,
                  const uint256_t *starting_perm, const uint256_t *last_perm,
                  int all, long long int *validated_keys,
#ifdef USE_MPI
                  int *signal, int verbose, int my_rank, int nprocs
#else
                  const int* signal
#endif
                  ) {
    // Declaration
    int status = 0;
    unsigned char current_key[AES256_KEY_SIZE];
    unsigned char current_cipher[AES_BLOCK_SIZE];
    uint256_key_iter *iter;

#ifdef USE_MPI
    int probe_flag = 0;
    long long int iter_count = 0;

    MPI_Request *requests;
    MPI_Status *statuses;
#endif

    // Allocation and initialization
    if((iter = uint256_key_iter_create(host_seed, starting_perm, last_perm)) == NULL) {
        perror("ERROR");

        return -1;
    }

#ifdef USE_MPI
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
#endif

    while(!uint256_key_iter_end(iter) && (all || !(*signal))) {
        if(validated_keys != NULL) {
            ++(*validated_keys);
        }
        uint256_key_iter_get(iter, current_key);

        // If encryption fails for some reason, break prematurely.
        if(aes256_ecb_encrypt(current_cipher, current_key, userId, sizeof(uuid_t))) {
            status = -1;
            break;
        }

        // If the new current_cipher is the same as the passed in client_cipher, set status to true
        // and break
        if(memcmp(current_cipher, client_cipher, sizeof(uuid_t)) == 0) {
            status = 1;

#ifdef USE_MPI
            *signal = 1;

            if(verbose) {
                fprintf(stderr, "INFO: Found by rank: %d, alerting ranks ...\n", my_rank);
            }

            memcpy(client_key, current_key, AES256_KEY_SIZE);

            if(!all) {
                // alert all ranks that the key was found, including yourself
                for (int i = 0; i < nprocs; i++) {
                    if(i != my_rank) {
                        MPI_Isend(signal, 1, MPI_INT, i, 0, MPI_COMM_WORLD,
                                  &(requests[i]));
                    }
                }

                for (int i = 0; i < nprocs; i++) {
                    if(i != my_rank) {
                        MPI_Wait(&(requests[i]), MPI_STATUS_IGNORE);
                    }
                }
            }
#else
            // Only have one thread copy the host_seed at a time
            // This might happen more than once if the # of threads exceeds the number of possible
            // keys
#pragma omp critical
            memcpy(client_key, current_key, AES256_KEY_SIZE);
            break;
#endif
        }

#ifdef USE_MPI
        if (!all && !(*signal) && iter_count % 128 == 0) {
            MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &probe_flag, MPI_STATUS_IGNORE);

            if(probe_flag) {
                MPI_Recv(signal, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD,
                        MPI_STATUS_IGNORE);
            }
        }
#endif

        uint256_key_iter_next(iter);
    }

    // Cleanup
#ifdef USE_MPI
    free(statuses);
    free(requests);
#endif
    uint256_key_iter_destroy(iter);

    return status;
}

/// Given a starting permutation, iterate forward through every possible permutation until one that's
/// matching last_perm is found, or until a matching public key is found.
/// \param client_priv_key An allocated corrupted key to fill if the corrupted key was found. Must
/// be at least 32 bytes big.
/// \param host_seed The original host seed (32 bytes).
/// \param EC_POINT * The client ECC Secp256r1 public key (see Sec. 2.3.3 of the SECG SEC 1).
/// \param starting_perm The permutation to start iterating from.
/// \param last_perm The final permutation to stop iterating at, inclusively.
/// \param signal A pointer to a shared value. Used to signal the function to prematurely leave.
/// \param all If benchmark mode is set to a non-zero value, then continue even if found.
/// \param validated_keys A counter to keep track of how many keys were traversed. If NULL, then this
/// is skipped.
/// \return Returns a 1 if found or a 0 if not. Returns a -1 if an error has occurred.
int ecc_validator(unsigned char *client_priv_key,
                  const unsigned char *host_seed, const EC_POINT *client_point,
                  const uint256_t *starting_perm, const uint256_t *last_perm,
                  const EC_GROUP *group, int all, long long int *validated_keys,
#ifdef USE_MPI
                  int *signal, int verbose, int my_rank, int nprocs
#else
                  const int* signal
#endif
                  ) {
    // Declarations
    int status = 0;
    int cmp_status;
    EC_POINT *curr_point;
    BN_CTX *ctx;
    BIGNUM *scalar;
    // This one changes, until status
    unsigned char current_priv_key[EC_PRIV_KEY_SIZE];
    uint256_key_iter *iter;

#ifdef USE_MPI
    int probe_flag = 0;
    long long int iter_count = 0;

    MPI_Request *requests;
    MPI_Status *statuses;
#endif

    // Allocation and initialization
    if((iter = uint256_key_iter_create(host_seed, starting_perm, last_perm)) == NULL) {
        perror("ERROR");
        return -1;
    }

    if((curr_point = EC_POINT_new(group)) == NULL) {
        fprintf(stderr, "ERROR: EC_POINT_new failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        uint256_key_iter_destroy(iter);

        return -1;
    }

    if((ctx = BN_CTX_new()) == NULL) {
        fprintf(stderr, "ERROR: BN_CTX_new failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        EC_POINT_free(curr_point);
        uint256_key_iter_destroy(iter);

        return -1;
    }

    BN_CTX_start(ctx);

    if((scalar = BN_CTX_get(ctx)) == NULL) {
        fprintf(stderr, "ERROR: BN_CTX_get failed.\nOpenSSL Error: %s\n",
                ERR_error_string(ERR_get_error(), NULL));

        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        EC_POINT_free(curr_point);
        uint256_key_iter_destroy(iter);

        return -1;
    }

#ifdef USE_MPI
    if((requests = malloc(sizeof(MPI_Request) * nprocs)) == NULL) {
        perror("Error");

        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        EC_POINT_free(curr_point);
        uint256_key_iter_destroy(iter);

        return -1;
    }

    if((statuses = malloc(sizeof(MPI_Status) * nprocs)) == NULL) {
        perror("Error");

        free(requests);

        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        EC_POINT_free(curr_point);
        uint256_key_iter_destroy(iter);

        return -1;
    }
#endif

    // While we haven't reached the end of iteration
    while(!uint256_key_iter_end(iter) && (all || !(*signal))) {
        if(validated_keys != NULL) {
            ++(*validated_keys);
        }
        // Get next current_priv_key
        uint256_key_iter_get(iter, current_priv_key);

        BN_bin2bn(current_priv_key, SEED_SIZE, scalar);

        if(!EC_POINT_mul(group, curr_point, scalar, NULL, NULL, ctx)) {
            fprintf(stderr, "ERROR: ECC_POINT_mul failed.\nOpenSSL Error: %s\n",
                    ERR_error_string(ERR_get_error(), NULL));
            status = -1;
            break;
        }

        if((cmp_status = EC_POINT_cmp(group, curr_point, client_point, ctx)) < 0) {
            fprintf(stderr, "ERROR: EC_POINT_cmp failed.\nOpenSSL Error: %s\n",
                    ERR_error_string(ERR_get_error(), NULL));
            status = -1;
            break;
        }
        // If the new cipher is the same as the passed in auth_cipher, set status to true and break
        else if(!cmp_status) {
            status = 1;

#ifdef USE_MPI
            *signal = 1;

            if(verbose) {
                fprintf(stderr, "INFO: Found by rank: %d, alerting ranks ...\n", my_rank);
            }

            memcpy(client_priv_key, current_priv_key, EC_PRIV_KEY_SIZE);

            if(!all) {
                // alert all ranks that the key was found, including yourself
                for (int i = 0; i < nprocs; i++) {
                    if(i != my_rank) {
                        MPI_Isend(signal, 1, MPI_INT, i, 0, MPI_COMM_WORLD,
                                  &(requests[i]));
                    }
                }

                for (int i = 0; i < nprocs; i++) {
                    if(i != my_rank) {
                        MPI_Wait(&(requests[i]), MPI_STATUS_IGNORE);
                    }
                }
            }
#else
            // Only have one thread copy the key at a time
            // This might happen more than once if the # of threads exceeds the number of possible
            // keys
#pragma omp critical
            memcpy(client_priv_key, current_priv_key, EC_PRIV_KEY_SIZE);
            break;
#endif
        }

#ifdef USE_MPI
        if (!all && !(*signal) && iter_count % 128 == 0) {
            MPI_Iprobe(MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, &probe_flag, MPI_STATUS_IGNORE);

            if(probe_flag) {
                MPI_Recv(signal, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD,
                        MPI_STATUS_IGNORE);
            }
        }
#endif

        uint256_key_iter_next(iter);
    }

    // Cleanup
#ifdef USE_MPI
    free(statuses);
    free(requests);
#endif

    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EC_POINT_free(curr_point);
    uint256_key_iter_destroy(iter);

    return status;
}

/// OpenMP implementation
/// \return Returns a 0 on successfully finding a match, a 1 when unable to find a match,
/// and a 2 when a general error has occurred.
int main(int argc, char *argv[]) {
#ifdef USE_MPI
    int my_rank, nprocs;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &nprocs);
#else
    int numcores;
#endif
    struct arguments arguments;
    static struct argp argp = {options, parse_opt, args_doc, prog_desc, 0, 0,
            0};

    uuid_t userId;
    char uuid_str[37];

    unsigned char host_seed[SEED_SIZE];
    unsigned char client_seed[SEED_SIZE];

    unsigned char client_cipher[AES_BLOCK_SIZE];
    EC_GROUP *ec_group;
    EC_POINT *client_ec_point;

    int mismatch, ending_mismatch;

    double start_time, duration, key_rate;
    long long int validated_keys = 0;
    int mode, found, subfound;

    uint256_t starting_perm, ending_perm;
    long long int sub_validated_keys;

#ifdef USE_MPI
    mpz_t key_count;
    size_t max_count;
#endif

#ifdef USE_MPI
    mpz_init(key_count);
#endif

    memset(&arguments, 0, sizeof(arguments));
    arguments.seed_hex = NULL;
    arguments.client_crypto_hex = NULL;
    arguments.uuid_hex = NULL;
    // Default to -1 for no mismatches provided, aka. go through all mismatches.
    arguments.mismatches = -1;
    arguments.subkey_length = SEED_SIZE * 8;

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    mismatch = 0;
    ending_mismatch = arguments.subkey_length;

    // If --fixed option was set, set the validation range to only use the --mismatches value.
    if (arguments.fixed) {
        mismatch = arguments.mismatches;
        ending_mismatch = arguments.mismatches;
    }
    // If --mismatches is set and non-negative, set the ending_mismatch to its value.
    else if(arguments.mismatches >= 0) {
        ending_mismatch = arguments.mismatches;
    }

#ifndef USE_MPI
    if (arguments.threads > 0) {
        omp_set_num_threads(arguments.threads);
    }

    // omp_get_num_threads() must be called in a parallel region, but
    // ensure that only one thread calls it
#pragma omp parallel default(none) shared(numcores)
#pragma omp single
    numcores = omp_get_num_threads();
#endif

    if(arguments.mode == MODE_ECC) {
        if((ec_group = EC_GROUP_new_by_curve_name(EC_CURVE)) == NULL) {
            fprintf(stderr, "ERROR: EC_GROUP_new_by_curve_name failed.\nOpenSSL Error: %s\n",
                    ERR_error_string(ERR_get_error(), NULL));

#ifdef OMP_DESTROY_SUPPORT
            if(omp_pause_resource_all(omp_pause_hard)) {
                fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
            }
#endif

            return ERROR_CODE_FAILURE;
        }

        if((client_ec_point = EC_POINT_new(ec_group)) == NULL) {
            fprintf(stderr, "ERROR: EC_POINT_new failed.\nOpenSSL Error: %s\n",
                    ERR_error_string(ERR_get_error(), NULL));

            EC_GROUP_free(ec_group);

#ifdef OMP_DESTROY_SUPPORT
            if(omp_pause_resource_all(omp_pause_hard)) {
                fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
            }
#endif

            return ERROR_CODE_FAILURE;
        }
    }

    if (arguments.random || arguments.benchmark) {
#ifdef USE_MPI
        if(my_rank == 0) {
#endif
            gmp_randstate_t randstate;

            // Set the gmp prng algorithm and set a seed based on the current time
            gmp_randinit_default(randstate);
            gmp_randseed_ui(randstate, (unsigned long) time(NULL));

            if (arguments.random) {
                fprintf(stderr, "WARNING: Random mode set. All three arguments will be ignored"
                                " and randomly generated ones will be used in their place.\n");
            } else if (arguments.benchmark) {
                fprintf(stderr, "WARNING: Benchmark mode set. All three arguments will be ignored"
                                " and randomly generated ones will be used in their place.\n");
            }

            get_random_seed(host_seed, SEED_SIZE, randstate);
            get_random_corrupted_seed(client_seed, host_seed, arguments.mismatches,
                                      arguments.subkey_length, randstate, arguments.benchmark,
#ifdef USE_MPI
                                      nprocs);
#else
                                      numcores);
#endif

            // Clear GMP PRNG
            gmp_randclear(randstate);

            if (arguments.mode == MODE_AES) {
                uuid_generate(userId);

                if (aes256_ecb_encrypt(client_cipher, client_seed, userId, sizeof(uuid_t))) {
                    fprintf(stderr, "ERROR: aes256_ecb_encrypt failed.\n");

#ifdef OMP_DESTROY_SUPPORT
                    if(omp_pause_resource_all(omp_pause_hard)) {
                        fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
                    }
#endif

                    return ERROR_CODE_FAILURE;
                }
            } else if (arguments.mode == MODE_ECC) {
                BIGNUM *scalar;

                if((scalar = BN_secure_new()) == NULL) {
                    fprintf(stderr, "ERROR: BN_CTX_new failed.\nOpenSSL Error: %s\n",
                            ERR_error_string(ERR_get_error(), NULL));

                    EC_POINT_free(client_ec_point);
                    EC_GROUP_free(ec_group);

#ifdef OMP_DESTROY_SUPPORT
                    if(omp_pause_resource_all(omp_pause_hard)) {
                        fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
                    }
#endif

                    return ERROR_CODE_FAILURE;
                }

                BN_bin2bn(client_seed, SEED_SIZE, scalar);

                if(!EC_POINT_mul(ec_group, client_ec_point, scalar, NULL, NULL, NULL)) {
                    fprintf(stderr, "ERROR: ECC_POINT_mul failed.\nOpenSSL Error: %s\n",
                            ERR_error_string(ERR_get_error(), NULL));

                    BN_clear_free(scalar);
                    EC_POINT_free(client_ec_point);
                    EC_GROUP_free(ec_group);

#ifdef OMP_DESTROY_SUPPORT
                    if(omp_pause_resource_all(omp_pause_hard)) {
                        fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
                    }
#endif

                    return ERROR_CODE_FAILURE;
                }

                BN_clear_free(scalar);
            }
#ifdef USE_MPI
        }

        // Broadcast all of the relevant variable to every rank
        MPI_Bcast(host_seed, SEED_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        MPI_Bcast(client_seed, SEED_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

        if(arguments.mode == MODE_AES) {
            MPI_Bcast(client_cipher, AES_BLOCK_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
            MPI_Bcast(userId, sizeof(uuid_t), MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        } else if(arguments.mode == MODE_ECC) {
            unsigned char client_public_key[100];
            int len;

            if (my_rank == 0) {
                if ((len = EC_POINT_point2oct(ec_group, client_ec_point, POINT_CONVERSION_COMPRESSED,
                                              client_public_key, sizeof(client_public_key),
                                              NULL)) == 0) {
                    fprintf(stderr, "ERROR: EC_POINT_point2oct failed.\nOpenSSL Error: %s\n",
                            ERR_error_string(ERR_get_error(), NULL));

                    EC_POINT_free(client_ec_point);
                    EC_GROUP_free(ec_group);

                    return ERROR_CODE_FAILURE;
                }
            }

            MPI_Bcast(&len, 1, MPI_INT, 0, MPI_COMM_WORLD);
            MPI_Bcast(client_public_key, len, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

            EC_POINT_oct2point(ec_group, client_ec_point, client_public_key, len, NULL);
        }
#endif
    }
    else {
        switch(parse_hex(host_seed, arguments.seed_hex)) {
            case 1:
                fprintf(stderr, "ERROR: KEY had non-hexadecimal characters.\n");

                if(arguments.mode == MODE_ECC) {
                    EC_POINT_free(client_ec_point);
                    EC_GROUP_free(ec_group);
                }

#ifdef OMP_DESTROY_SUPPORT
                if(omp_pause_resource_all(omp_pause_hard)) {
                    fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
                }
#endif

                return ERROR_CODE_FAILURE;
            case 2:
                fprintf(stderr, "ERROR: KEY did not have even length.\n");

                if(arguments.mode == MODE_ECC) {
                    EC_POINT_free(client_ec_point);
                    EC_GROUP_free(ec_group);
                }

#ifdef OMP_DESTROY_SUPPORT
                if(omp_pause_resource_all(omp_pause_hard)) {
                    fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
                }
#endif

                return ERROR_CODE_FAILURE;
            default:
                break;
        }

        if(arguments.mode == MODE_AES) {
            switch(parse_hex(client_cipher, arguments.client_crypto_hex)) {
                case 1:
                    fprintf(stderr, "ERROR: CIPHER had non-hexadecimal characters.\n");

#ifdef OMP_DESTROY_SUPPORT
                    if(omp_pause_resource_all(omp_pause_hard)) {
                        fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
                    }
#endif

                    return ERROR_CODE_FAILURE;
                case 2:
                    fprintf(stderr, "ERROR: CIPHER did not have even length.\n");

#ifdef OMP_DESTROY_SUPPORT
                    if(omp_pause_resource_all(omp_pause_hard)) {
                        fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
                    }
#endif

                    return ERROR_CODE_FAILURE;
                default:
                    break;
            }

            if (uuid_parse(arguments.uuid_hex, userId) < 0) {
                fprintf(stderr, "ERROR: UUID not in canonical form.\n");

#ifdef OMP_DESTROY_SUPPORT
                if(omp_pause_resource_all(omp_pause_hard)) {
                    fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
                }
#endif

                return ERROR_CODE_FAILURE;
            }
        }
        else if(arguments.mode == MODE_ECC) {
            if(EC_POINT_hex2point(ec_group, arguments.client_crypto_hex, client_ec_point, NULL) == NULL) {
                fprintf(stderr, "ERROR: EC_POINT_hex2point failed.\nOpenSSL Error: %s\n",
                        ERR_error_string(ERR_get_error(), NULL));

                EC_POINT_free(client_ec_point);
                EC_GROUP_free(ec_group);

#ifdef OMP_DESTROY_SUPPORT
                if(omp_pause_resource_all(omp_pause_hard)) {
                    fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
                }
#endif

                return ERROR_CODE_FAILURE;
            }
        }
    }

    if (arguments.verbose
#ifdef USE_MPI
        && my_rank == 0
#endif
    ) {
        fprintf(stderr, "INFO: Using HOST_SEED: ");
        if(arguments.mode == MODE_ECC) {
            fprintf(stderr, "                       ");
        }
        fprint_hex(stderr, host_seed, SEED_SIZE);
        fprintf(stderr, "\n");

        if(arguments.random || arguments.benchmark) {
            fprintf(stderr, "INFO: Using CLIENT_SEED (%d mismatches): ",
                    arguments.mismatches);
            if(arguments.mode == MODE_ECC) {
                fprintf(stderr, "      ");
            }
            fprint_hex(stderr, client_seed, SEED_SIZE);
            fprintf(stderr, "\n");
        }

        if(arguments.mode == MODE_AES) {
            fprintf(stderr, "INFO: Using AES-256 Host Key: ");
            fprint_hex(stderr, host_seed, SEED_SIZE);
            fprintf(stderr, "\n");

            fprintf(stderr, "INFO: AES-256 CLIENT_CIPHER:  ");
            fprint_hex(stderr, client_cipher, AES_BLOCK_SIZE);
            fprintf(stderr, "\n");

            // Convert the uuid to a string for printing
            uuid_unparse(userId, uuid_str);

            fprintf(stderr, "INFO: Using UUID:             %s\n", uuid_str);
        }
        else if(arguments.mode == MODE_ECC) {
            if(arguments.random || arguments.benchmark) {
                fprintf(stderr, "INFO: Using ECC Secp256r1 Host Public Key:    ");
                if(fprintf_ec_point(stderr, ec_group, client_ec_point, POINT_CONVERSION_COMPRESSED,
                                 NULL)) {
                    fprintf(stderr, "ERROR: fprintf_ec_point failed.\n");

                    EC_POINT_free(client_ec_point);
                    EC_GROUP_free(ec_group);

#ifdef OMP_DESTROY_SUPPORT
                    if(omp_pause_resource_all(omp_pause_hard)) {
                        fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
                    }
#endif

                    return ERROR_CODE_FAILURE;
                }
                fprintf(stderr, "\n");
            }

            fprintf(stderr, "INFO: Using ECC Secp256r1 Client Public Key:  ");
            if(fprintf_ec_point(stderr, ec_group, client_ec_point, POINT_CONVERSION_COMPRESSED,
                             NULL)) {
                fprintf(stderr, "ERROR: fprintf_ec_point failed.\n");

                EC_POINT_free(client_ec_point);
                EC_GROUP_free(ec_group);

#ifdef OMP_DESTROY_SUPPORT
                if(omp_pause_resource_all(omp_pause_hard)) {
                    fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
                }
#endif

                return ERROR_CODE_FAILURE;
            }
            fprintf(stderr, "\n");
        }
    }

    // mode needs to be copied for OpenMP shared access
    mode = arguments.mode;
    found = 0;

#ifdef USE_MPI
    start_time = MPI_Wtime();
#else
    start_time = omp_get_wtime();
#endif

    for (; mismatch <= ending_mismatch && !found; mismatch++) {
        if(arguments.verbose
#ifdef USE_MPI
            && my_rank == 0
#endif
        ) {
            fprintf(stderr, "INFO: Checking a hamming distance of %d...\n", mismatch);
        }

#ifdef USE_MPI
        mpz_bin_uiui(key_count, arguments.subkey_length, mismatch);

        // Only have this rank run if it's within range of possible keys
        if(mpz_cmp_ui(key_count, (unsigned long)my_rank) > 0) {
            max_count = nprocs;
            // Set the count of pairs to the range of possible keys if there are more ranks
            // than possible keys
            if(mpz_cmp_ui(key_count, nprocs) < 0) {
                max_count = mpz_get_ui(key_count);
            }

            uint256_get_perm_pair(&starting_perm, &ending_perm, (size_t)my_rank, max_count,
                                  mismatch, arguments.subkey_length);

            if (mode == MODE_AES) {
                subfound = aes_validator(client_seed, host_seed, client_cipher, userId,
                                         &starting_perm, &ending_perm, arguments.all,
                                         arguments.count ? &sub_validated_keys : NULL, &found,
                                         arguments.verbose, my_rank, max_count);
            } else if (mode == MODE_ECC) {
                subfound = ecc_validator(client_seed, host_seed, client_ec_point,
                                         &starting_perm, &ending_perm, ec_group, arguments.all,
                                         arguments.count ? &sub_validated_keys : NULL, &found,
                                         arguments.verbose, my_rank, max_count);
            }

            if (subfound < 0) {
                // Cleanup
                mpz_clear(key_count);

                EC_POINT_free(client_ec_point);
                EC_GROUP_free(ec_group);

                MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
            }
        }
#else
#pragma omp parallel default(none) shared(mode, found, host_seed, client_seed, client_cipher,\
            userId, ec_group, client_ec_point, mismatch, arguments, validated_keys)\
            private(subfound, starting_perm, ending_perm, sub_validated_keys)
        {
            sub_validated_keys = 0;

            uint256_get_perm_pair(&starting_perm, &ending_perm, (size_t) omp_get_thread_num(),
                                  (size_t) omp_get_num_threads(), mismatch,
                                  arguments.subkey_length);

            if (mode == MODE_AES) {
                subfound = aes_validator(client_seed, host_seed, client_cipher, userId,
                                         &starting_perm, &ending_perm, arguments.all,
                                         arguments.count ? &sub_validated_keys : NULL,
                                         &found);
            } else if (mode == MODE_ECC) {
                subfound = ecc_validator(client_seed, host_seed, client_ec_point,
                                         &starting_perm, &ending_perm, ec_group, arguments.all,
                                         arguments.count ? &sub_validated_keys : NULL,
                                         &found);
            }


#pragma omp critical
            {
                // If the result is positive set the "global" found to 1. Will cause the other
                // threads to prematurely stop.
                if (subfound > 0) {
                    // If it isn't already found nor is there an error found,
                    if (!found) {
                        found = 1;
                    }
                }
                // If the result is negative, set a flag that an error has occurred, and stop the other
                // threads. Will cause the other threads to prematurely stop.
                else if (subfound < 0) {
                    found = -1;
                }

                if (arguments.count) {
                    validated_keys += sub_validated_keys;
                }
            }
        }
#endif
    }

    if(arguments.mode == MODE_ECC) {
        EC_POINT_free(client_ec_point);
        EC_GROUP_free(ec_group);
    }

#ifdef USE_MPI
    if((mismatch <= ending_mismatch) && !(arguments.all) && subfound == 0 && !found) {
        fprintf(stderr, "Rank %d Bleh\n", my_rank);
        MPI_Recv(&found, 1, MPI_INT, MPI_ANY_SOURCE, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
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
        if(arguments.mode == MODE_AES || arguments.mode == MODE_ECC) {
            fprint_hex(stdout, client_seed, SEED_SIZE);
        }
        printf("\n");
    }

    // Cleanup
    mpz_clear(key_count);

    MPI_Finalize();

//    if(my_rank == 0) {
//        return found ? ERROR_CODE_FOUND : ERROR_CODE_NOT_FOUND;
//    }
//    else {
//        return ERROR_CODE_FOUND;
//    }

    return EXIT_SUCCESS;
#else
    // Check if an error occurred in one of the threads.
    if(found < 0) {
        if(omp_pause_resource_all(omp_pause_hard)) {
            fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
        }

        return ERROR_CODE_FAILURE;
    }

    duration = omp_get_wtime() - start_time;

    if(arguments.verbose) {
        fprintf(stderr, "INFO: Clock time: %f s\n", duration);
        fprintf(stderr, "INFO: Found: %d\n", found);
    }

    if(arguments.count) {
        // Divide validated_keys by duration
        key_rate = (double)validated_keys / duration;

        fprintf(stderr, "INFO: Keys searched: %lld\n", validated_keys);
        fprintf(stderr, "INFO: Keys per second: %.9g\n", key_rate);
    }

    if(found > 0) {
        if(arguments.mode == MODE_AES || arguments.mode == MODE_ECC) {
            fprint_hex(stdout, client_seed, SEED_SIZE);
        }
        printf("\n");
    }

#ifdef OMP_DESTROY_SUPPORT
    if(omp_pause_resource_all(omp_pause_hard)) {
        fprintf(stderr, "ERROR: omp_pause_resource_all failed.");
    }
#endif

    return found ? ERROR_CODE_FOUND : ERROR_CODE_NOT_FOUND;
#endif
}
