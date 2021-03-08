//
// Created by cp723 on 2/7/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <uuid/uuid.h>
#include <argp.h>

#if defined(USE_MPI)
#include <mpi.h>
#else
#include <omp.h>
#endif

#include "validator.h"
#include "crypto/cipher.h"
#include "crypto/ec.h"
#include "seed_iter.h"
#include "perm.h"
#include "util.h"

#define ERROR_CODE_FOUND 0
#define ERROR_CODE_NOT_FOUND 1
#define ERROR_CODE_FAILURE 2

// If using OpenMP, and using Clang 10+ or GCC 9+, support omp_pause_resource_all
#if !defined(USE_MPI) && ((defined(__clang__) && __clang_major__ >= 10) || (!defined(__clang) && \
    __GNUC__ >= 9))
#define OMP_DESTROY()\
if(omp_pause_resource_all(omp_pause_hard)) {\
    fprintf(stderr, "ERROR: omp_pause_resource_all failed.");\
}
#else
#define OMP_DESTROY()
#endif

// By setting it to 0, we're assuming it'll be zeroified when arguments are first created
#define MODE_NONE 0
// Used with symmetric encryption
#define MODE_CIPHER 1
// Used with matching a public key
#define MODE_EC 2

typedef struct algo {
    const char *abbr_name;
    const char *full_name;
    int nid;
    int mode;
} algo;

const algo supported_algos[] = {
        {"none", "None", 0, MODE_NONE },
        // Cipher algorithms
        { "aes","AES-256-ECB", NID_aes_256_ecb, MODE_CIPHER },
        { "chacha20","ChaCha20", NID_chacha20, MODE_CIPHER },
        // EC algorithms
        { "ecc","Secp256r1", NID_X9_62_prime256v1, MODE_EC },
        { 0 }
};

#ifdef USE_MPI
const char *argp_program_version = "rbc_validator_mpi (MPI) 0.1.0";
#else
const char *argp_program_version = "rbc_validator (OpenMP) 0.1.0";
#endif
const char *argp_program_bug_address = "<cp723@nau.edu>";
error_t argp_err_exit_status = ERROR_CODE_FAILURE;

static char args_doc[] = "--mode=none HOST_SEED\n"
                         "--mode=[aes,chacha20] HOST_SEED CLIENT_CIPHER UUID [IV]\n"
                         "--mode=ecc HOST_SEED CLIENT_PUB_KEY\n"
                         "--mode=* -r/--random -m/--mismatches=value";
static char prog_desc[] = "Given an HOST_SEED and either:"
                          "\n1) an AES256 CLIENT_CIPHER and plaintext UUID;"
                          "\n2) a ChaCha20 CLIENT_CIPHER, plaintext UUID, and IV;"
                          "\n3) an ECC Secp256r1 CLIENT_PUB_KEY;"
                          "\nwhere CLIENT_* is from an unreliable source."
                          " Progressively corrupt the chosen cryptographic function by a certain"
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
                          " characters.";

struct arguments {
    const algo *algo;
    int verbose, benchmark, random, fixed, count, all;
    char *seed_hex, *client_crypto_hex, *uuid_hex, *iv_hex;
    int mismatches, subseed_length;
#ifndef USE_MPI
    int threads;
#endif
};

static struct argp_option options[] = {
    {
        "mode",
        // Use the non-printable ASCII character '\5' to always enforce long mode (--mode)
        '\5',
        "[none,aes,chacha20,ecc]",
        0,
        "REQUIRED. Choose between only seed iteration (none), AES256 (aes), ChaCha20 (chacha20),"
        " and ECC Secp256r1 (ecc).",
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
        "Instead of using arguments, randomly generate HOST_SEED and CLIENT_*. This must be"
        " accompanied by --mismatches, since it is used to corrupt the random key by the same # of"
        " bits. --random and --benchmark cannot be used together.",
        0},
    {
        "benchmark",
        'b',
        0,
        0,
        "Instead of using arguments, strategically generate HOST_SEED and CLIENT_*."
        " Specifically, generates a client seed that's always 50% of the way through a rank's"
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

const algo *find_algo(const char* abbr_name, const algo *algos) {
    while(algos->abbr_name != NULL) {
        if(!strcmp(abbr_name, algos->abbr_name)) {
            return algos;
        }
        algos++;
    }

    return NULL;
}

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct arguments *arguments = state->input;

    // Used for strtol
    char *endptr;
    long value;

    switch(key) {
        case '\5':
            if((arguments->algo = find_algo(arg, supported_algos)) == NULL) {
                argp_error(state, "--mode is invalid or unsupported.\n");
            }
            break;
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

            arguments->subseed_length = (int)value;

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
            if(arguments->random || arguments->benchmark) {
                argp_usage(state);
            }

            switch(state->arg_num) {
                case 0:
                    if(strlen(arg) != SEED_SIZE * 2) {
                        argp_error(state, "HOST_SEED must be 256-bits long.\n");
                    }
                    arguments->seed_hex = arg;
                    break;
                case 1:
                    if(arguments->algo->mode == MODE_CIPHER) {
                        const EVP_CIPHER *evp_cipher = EVP_get_cipherbynid(arguments->algo->nid);
                        if(evp_cipher == NULL) {
                            argp_error(state, "Not a valid EVP cipher nid.\n");
                        }
                        size_t block_len = EVP_CIPHER_block_size(evp_cipher);
                        if(strlen(arg) % block_len * 2 != 0) {
                            argp_error(state, "CLIENT_CIPHER not a multiple of the block size"
                                              " %zu bytes for %s\n",
                                       block_len, arguments->algo->full_name);
                        }
                    }
                    else if(arguments->algo->mode == MODE_EC) {
                        EC_GROUP *group = EC_GROUP_new_by_curve_name(arguments->algo->nid);
                        if(group == NULL) {
                            argp_error(state, "EC_GROUP_new_by_curve_name failed.\n");
                        }
                        size_t order_len = (EC_GROUP_order_bits(group) + 7) / 8;
                        size_t comp_len = order_len + 1;
                        size_t uncomp_len = (order_len * 2) + 1;
                        if(strlen(arg) != comp_len * 2 && strlen(arg) != uncomp_len * 2) {
                            argp_error(state, "CLIENT_PUB_KEY not %zu nor %zu bytes for %s\n",
                                       comp_len, uncomp_len, arguments->algo->full_name);
                        }
                        EC_GROUP_free(group);
                    }
                    arguments->client_crypto_hex = arg;
                    break;
                case 2:
                    if(arguments->algo->mode == MODE_CIPHER) {
                        size_t uuid_hex_len = (sizeof(uuid_t) * 2) + 4;
                        if(strlen(arg) != uuid_hex_len) {
                            argp_error(state, "UUID not %zu characters long.\n", uuid_hex_len);
                        }
                        arguments->uuid_hex = arg;
                    }
                    else {
                        argp_usage(state);
                    }
                    break;
                case 3:
                    if(arguments->algo->mode == MODE_CIPHER) {
                        const EVP_CIPHER *evp_cipher = EVP_get_cipherbynid(arguments->algo->nid);
                        if(evp_cipher == NULL) {
                            argp_error(state, "Not a valid EVP cipher nid.\n");
                        }
                        if(EVP_CIPHER_iv_length(evp_cipher) == 0) {
                            argp_error(state, "The chosen cipher doesn't require an IV.\n");
                        }
                        if(strlen(arg) != EVP_CIPHER_iv_length(evp_cipher) * 2) {
                            argp_error(state, "Length of IV doesn't match the chosen cipher's"
                                              " required IV length match\n");
                        }
                        arguments->iv_hex = arg;
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
            if(arguments->algo == NULL) {
                argp_error(state, "--mode is required!\n");
            }

            if(!(arguments->random) && !(arguments->benchmark)) {
                // We don't need to check seed_hex since the first argument will always be set to it
                // and NO_ARGS is checked above
                if(arguments->algo->mode != MODE_NONE && arguments->client_crypto_hex == NULL) {
                    argp_usage(state);
                }

                if(arguments->algo->mode == MODE_CIPHER && arguments->uuid_hex == NULL) {
                    argp_usage(state);
                }
            }
            // No argument should be set if in random or benchmark mode
            else if(arguments->seed_hex != NULL) {
                argp_usage(state);
            }

            if(arguments->random && arguments->benchmark) {
                argp_error(state, "--random and --benchmark cannot be both set simultaneously.\n");
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

            if(arguments->mismatches > arguments->subseed_length) {
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

int parse_hex_handler(unsigned char *buffer, const char *hex) {
    int status = parse_hex(buffer, hex);

    if(status == 1) {
        fprintf(stderr, "ERROR: CIPHER had non-hexadecimal characters.\n");
    }
    else if(status == 2) {
        fprintf(stderr, "ERROR: CIPHER did not have even length.\n");
    }

    return status != 0;
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

    const EVP_CIPHER *evp_cipher;
    unsigned char client_cipher[EVP_MAX_BLOCK_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    EC_GROUP *ec_group;
    EC_POINT *client_ec_point;

    int mismatch, ending_mismatch;

    double start_time, duration, key_rate;
    long long int validated_keys = 0;
    int found, subfound;

#ifdef USE_MPI
    mpz_t key_count;
    size_t max_count;
#endif

    memset(&arguments, 0, sizeof(arguments));
    arguments.seed_hex = NULL;
    arguments.client_crypto_hex = NULL;
    arguments.uuid_hex = NULL;
    // Default to -1 for no mismatches provided, aka. go through all mismatches.
    arguments.mismatches = -1;
    arguments.subseed_length = SEED_SIZE * 8;

    // Parse arguments
    argp_parse(&argp, argc, argv, 0, 0, &arguments);

    mismatch = 0;
    ending_mismatch = arguments.subseed_length;

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

    // Memory alloc/init
    if(arguments.algo->mode == MODE_CIPHER) {
        evp_cipher = EVP_get_cipherbynid(arguments.algo->nid);
    }
    else if(arguments.algo->mode == MODE_EC) {
        if((ec_group = EC_GROUP_new_by_curve_name(arguments.algo->nid)) == NULL) {
            fprintf(stderr, "ERROR: EC_GROUP_new_by_curve_name failed.\nOpenSSL Error: %s\n",
                    ERR_error_string(ERR_get_error(), NULL));

            OMP_DESTROY()

            return ERROR_CODE_FAILURE;
        }

        if((client_ec_point = EC_POINT_new(ec_group)) == NULL) {
            fprintf(stderr, "ERROR: EC_POINT_new failed.\nOpenSSL Error: %s\n",
                    ERR_error_string(ERR_get_error(), NULL));

            EC_GROUP_free(ec_group);

            OMP_DESTROY()

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

            get_random_seed(host_seed, SEED_SIZE, randstate);
            get_random_corrupted_seed(client_seed, host_seed, arguments.mismatches, SEED_SIZE,
                                      arguments.subseed_length, randstate, arguments.benchmark,
#ifdef USE_MPI
                                      nprocs);
#else
                                      numcores);
#endif

            if(arguments.algo->mode == MODE_CIPHER && EVP_CIPHER_iv_length(evp_cipher) > 0) {
                get_random_seed(iv, EVP_CIPHER_iv_length(evp_cipher), randstate);
            }

            // Clear GMP PRNG
            gmp_randclear(randstate);

            if(arguments.algo->mode == MODE_CIPHER) {
                uuid_generate(userId);

                if(evp_encrypt(client_cipher, NULL, evp_cipher, client_seed, userId,
                               sizeof(uuid_t), iv)) {
                    fprintf(stderr, "ERROR: Initial encryption failed.\nOpenSSL Error: %s\n",
                            ERR_error_string(ERR_get_error(), NULL));

                    OMP_DESTROY()

                    return ERROR_CODE_FAILURE;
                }
            }
            else if (arguments.algo->mode == MODE_EC) {
                if(get_ec_public_key(client_ec_point, NULL, ec_group, client_seed, SEED_SIZE)) {
                    EC_POINT_free(client_ec_point);
                    EC_GROUP_free(ec_group);

                    OMP_DESTROY()

                    return ERROR_CODE_FAILURE;
                }
            }
#ifdef USE_MPI
        }

        // Broadcast all of the relevant variable to every rank
        MPI_Bcast(host_seed, SEED_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        MPI_Bcast(client_seed, SEED_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

        if(arguments.algo->mode == MODE_CIPHER) {
            MPI_Bcast(client_cipher, sizeof(uuid_t), MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
            MPI_Bcast(userId, sizeof(uuid_t), MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        }
        else if(arguments.algo->mode == MODE_EC) {
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
        int parse_status = parse_hex_handler(host_seed, arguments.seed_hex);

        if(!parse_status) {
            if(arguments.algo->mode == MODE_CIPHER) {
                parse_status = parse_hex_handler(client_cipher, arguments.client_crypto_hex);

                if(!parse_status && uuid_parse(arguments.uuid_hex, userId) < 0) {
                    fprintf(stderr, "ERROR: UUID not in canonical form.\n");
                    parse_status = 1;
                }

                if (!parse_status && arguments.iv_hex != NULL) {
                    parse_status = parse_hex_handler(iv, arguments.iv_hex);
                }
            }
            else if (arguments.algo->mode == MODE_EC) {
                if (EC_POINT_hex2point(ec_group, arguments.client_crypto_hex,
                                       client_ec_point, NULL) == NULL) {
                    fprintf(stderr, "ERROR: EC_POINT_hex2point failed.\nOpenSSL Error: %s\n",
                            ERR_error_string(ERR_get_error(), NULL));
                    parse_status = 1;
                }
            }
        }

        if(parse_status) {
            if(arguments.algo->mode == MODE_EC) {
                EC_POINT_free(client_ec_point);
                EC_GROUP_free(ec_group);
            }
            OMP_DESTROY()

            return ERROR_CODE_FAILURE;
        }
    }

    if (arguments.verbose
#ifdef USE_MPI
        && my_rank == 0
#endif
    ) {
        fprintf(stderr, "INFO: Using HOST_SEED:                  ");
        fprint_hex(stderr, host_seed, SEED_SIZE);
        fprintf(stderr, "\n");

        if(arguments.random || arguments.benchmark) {
            fprintf(stderr, "INFO: Using CLIENT_SEED (%d mismatches): ",
                    arguments.mismatches);
            fprint_hex(stderr, client_seed, SEED_SIZE);
            fprintf(stderr, "\n");
        }

        if(arguments.algo->mode == MODE_CIPHER) {
            fprintf(stderr, "INFO: Using %s CLIENT_CIPHER: %*s", arguments.algo->full_name,
                    (int)strlen(arguments.algo->full_name) - 4, "");
            fprint_hex(stderr, client_cipher, sizeof(uuid_t));
            fprintf(stderr, "\n");

            // Convert the uuid to a string for printing
            uuid_unparse(userId, uuid_str);
            fprintf(stderr, "INFO: Using UUID:                       %s\n", uuid_str);

            if(EVP_CIPHER_iv_length(evp_cipher) > 0) {
                fprintf(stderr, "INFO: Using IV:                         ");
                fprint_hex(stderr, iv, EVP_CIPHER_iv_length(evp_cipher));
                fprintf(stderr, "\n");
            }
        }
        else if(arguments.algo->mode == MODE_EC) {
            if(arguments.random || arguments.benchmark) {
                fprintf(stderr, "INFO: Using %s HOST_PUB_KEY:%*s",
                        arguments.algo->full_name, (int)strlen(arguments.algo->full_name) - 4, "");
                if(fprintf_ec_point(stderr, ec_group, client_ec_point, POINT_CONVERSION_COMPRESSED,
                                    NULL)) {
                    fprintf(stderr, "ERROR: fprintf_ec_point failed.\n");

                    EC_POINT_free(client_ec_point);
                    EC_GROUP_free(ec_group);

                    OMP_DESTROY()

                    return ERROR_CODE_FAILURE;
                }
                fprintf(stderr, "\n");
            }

            fprintf(stderr, "INFO: Using %s CLIENT_PUB_KEY:%*s", arguments.algo->full_name,
                    (int)strlen(arguments.algo->full_name) - 6, "");
            if(fprintf_ec_point(stderr, ec_group, client_ec_point, POINT_CONVERSION_COMPRESSED,
                                NULL)) {
                fprintf(stderr, "ERROR: fprintf_ec_point failed.\n");

                EC_POINT_free(client_ec_point);
                EC_GROUP_free(ec_group);

                OMP_DESTROY()

                return ERROR_CODE_FAILURE;
            }
            fprintf(stderr, "\n");
        }
    }

    found = 0;

#ifdef USE_MPI
    mpz_init(key_count);

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

#ifndef USE_MPI
#pragma omp parallel default(none) shared(found, host_seed, client_seed, evp_cipher, client_cipher, iv,\
            userId, ec_group, client_ec_point, mismatch, arguments, validated_keys)\
            private(subfound)
        {
        long long int sub_validated_keys = 0;
#endif

        int (*crypto_func)(const unsigned char*, void*) = NULL;
        int (*crypto_cmp)(void*) = NULL;

        void *v_args = NULL;

        subfound = 0;

        if(arguments.algo->mode == MODE_CIPHER) {
#ifndef ALWAYS_EVP_AES
            // Use a custom implementation for improved speed
            if(arguments.algo->nid == NID_aes_256_ecb) {
                crypto_func = aes256_crypto_func;
                crypto_cmp = aes256_crypto_cmp;
            }
            else {
#endif
                crypto_func = cipher_crypto_func;
                crypto_cmp = cipher_crypto_cmp;
#ifndef ALWAYS_EVP_AES
            }
#endif

            v_args = cipher_validator_create(evp_cipher, client_cipher, userId, sizeof(uuid_t),
                                             EVP_CIPHER_iv_length(evp_cipher) > 0 ? iv : NULL);
        }
        else if(arguments.algo->mode == MODE_EC) {
            crypto_func = ec_crypto_func;
            crypto_cmp = ec_crypto_cmp;
            v_args = ec_validator_create(ec_group, client_ec_point);
        }

#ifdef USE_MPI
        mpz_bin_uiui(key_count, arguments.subseed_length, mismatch);

        // Only have this rank run if it's within range of possible keys
        if(mpz_cmp_ui(key_count, (unsigned long)my_rank) > 0) {
            mpz_t first_perm, last_perm;

            mpz_inits(first_perm, last_perm, NULL);

            max_count = nprocs;
            // Set the count of pairs to the range of possible keys if there are more ranks
            // than possible keys
            if(mpz_cmp_ui(key_count, nprocs) < 0) {
                max_count = mpz_get_ui(key_count);
            }

            get_perm_pair(first_perm, last_perm, (size_t)my_rank, max_count,
                              mismatch, arguments.subseed_length);

            subfound = find_matching_seed(client_seed, host_seed, first_perm, last_perm,
                                          arguments.all,
                                          arguments.count ? &validated_keys : NULL,
                                          &found, arguments.verbose, my_rank, max_count,
                                          crypto_func, crypto_cmp, v_args);

            mpz_clears(first_perm, last_perm, NULL);

            if (subfound < 0) {
                // Cleanup
                mpz_clear(key_count);

                if(arguments.algo->mode == MODE_CIPHER) {
                    if(arguments.algo->nid != NID_aes_256_ecb) {
                        cipher_validator_destroy(v_args);
                    }
                }
                else if(arguments.algo->mode == MODE_EC) {
                    ec_validator_destroy(v_args);

                    EC_POINT_free(client_ec_point);
                    EC_GROUP_free(ec_group);
                }

                MPI_Abort(MPI_COMM_WORLD, ERROR_CODE_FAILURE);
            }
        }
#else
        if(subfound >= 0) {
            mpz_t first_perm, last_perm;

            mpz_inits(first_perm, last_perm, NULL);

            get_perm_pair(first_perm, last_perm, (size_t) omp_get_thread_num(),
                          (size_t) omp_get_num_threads(), mismatch,
                          arguments.subseed_length);

            subfound = find_matching_seed(client_seed, host_seed, first_perm, last_perm,
                                          arguments.all,
                                          arguments.count ? &sub_validated_keys : NULL,
                                          &found, crypto_func, crypto_cmp, v_args);

            mpz_clears(first_perm, last_perm, NULL);
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

                validated_keys += sub_validated_keys;
            }
#endif

            if(arguments.algo->mode == MODE_CIPHER) {
                cipher_validator_destroy(v_args);
            }
            else if(arguments.algo->mode == MODE_EC) {
                ec_validator_destroy(v_args);
            }
#ifndef USE_MPI
        }
#endif
    }

    if(arguments.algo->mode == MODE_EC) {
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
        fprint_hex(stdout, client_seed, SEED_SIZE);
        printf("\n");
    }

    // Cleanup
    mpz_clear(key_count);

    MPI_Finalize();

    return EXIT_SUCCESS;
#else
    // Check if an error occurred in one of the threads.
    if(found < 0) {
        OMP_DESTROY()

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
        fprint_hex(stdout, client_seed, SEED_SIZE);
        printf("\n");
    }

    OMP_DESTROY()

    return found || arguments.algo->mode == MODE_NONE ? ERROR_CODE_FOUND : ERROR_CODE_NOT_FOUND;
#endif
}
