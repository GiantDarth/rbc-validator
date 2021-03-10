//
// Created by cp723 on 2/7/2019.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#if defined(USE_MPI)
#include <mpi.h>
#include "cmdline/cmdline_mpi.h"
#else
#include <omp.h>
#include "cmdline/cmdline_omp.h"
#endif

#include "validator.h"
#include "crypto/cipher.h"
#include "crypto/ec.h"
#include "seed_iter.h"
#include "perm.h"
#include "uuid.h"
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

struct params {
    char *seed_hex, *client_crypto_hex, *uuid_hex, *iv_hex;
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

int validate_args(const struct gengetopt_args_info *args_info) {
    const algo *algo = &(supported_algos[args_info->mode_arg]);

    if (args_info->mismatches_arg > SEED_SIZE * 8) {
        fprintf(stderr, "--mismatches cannot exceed the seed size of 256-bits.\n");
        return 1;
    }

    if (args_info->subkey_arg > SEED_SIZE * 8) {
        fprintf(stderr, "--subkey cannot exceed the seed size of 256-bits.\n");
        return 1;
    }
    else if (args_info->subkey_arg < 1) {
        fprintf(stderr, "--subkey must be at least 1.\n");
        return 1;
    }

#ifndef USE_MPI
    if(args_info->threads_arg > omp_get_thread_limit()) {
        fprintf(stderr, "--threads exceeds program thread limit.\n");
        return 1;
    }
#endif

    if(args_info->inputs_num == 0) {
        if(!args_info->random_flag && !args_info->benchmark_flag) {
            fprintf(stderr, "%s\n", gengetopt_args_info_usage);
            return 1;
        }
    }
    else if(algo->mode == MODE_NONE || args_info->random_flag || args_info->benchmark_flag) {
        fprintf(stderr, "%s\n", gengetopt_args_info_usage);
        return 1;
    }

    if(args_info->mismatches_arg < 0) {
        if(args_info->random_flag) {
            fprintf(stderr, "--mismatches must be set and non-negative when using --random.\n");
            return 1;
        }
        if(args_info->benchmark_flag) {
            fprintf(stderr, "--mismatches must be set and non-negative when using --benchmark.\n");
            return 1;
        }
        if(args_info->fixed_flag) {
            fprintf(stderr, "--mismatches must be set and non-negative when using --fixed.\n");
            return 1;
        }
    }
    else if(args_info->mismatches_arg > args_info->subkey_arg) {
        fprintf(stderr, "--mismatches cannot be set larger than --subkey.\n");
        return 1;
    }

    return 0;
}

int parse_params(struct params *params, const struct gengetopt_args_info *args_info) {
    if(args_info->inputs_num < 1) {
        return 0;
    }

    if(strlen(args_info->inputs[0]) != SEED_SIZE * 2) {
        fprintf(stderr, "HOST_SEED must be %d byte(s) long.\n", SEED_SIZE);
        return 1;
    }

    params->seed_hex = args_info->inputs[0];

    const algo *algo = find_algo(args_info->mode_orig, supported_algos);

    if(algo->mode == MODE_NONE && args_info->inputs_num != 1) {
        fprintf(stderr, "%s\n", gengetopt_args_info_usage);
        return 1;
    }
    else if(algo->mode == MODE_CIPHER) {
        if(args_info->inputs_num < 3 || args_info->inputs_num > 4) {
            fprintf(stderr, "%s\n", gengetopt_args_info_usage);
            return 1;
        }

        const EVP_CIPHER *evp_cipher = EVP_get_cipherbynid(algo->nid);
        if (evp_cipher == NULL) {
            fprintf(stderr, "Not a valid EVP cipher nid.\n");
            return 1;
        }
        size_t block_len = EVP_CIPHER_block_size(evp_cipher);
        if (strlen(args_info->inputs[1]) % block_len * 2 != 0) {
            fprintf(stderr, "CLIENT_CIPHER not a multiple of the block size %zu bytes for %s\n",
                    block_len, algo->full_name);
            return 1;
        }

        params->client_crypto_hex = args_info->inputs[1];

        if(strlen(args_info->inputs[2]) != UUID_STR_LEN) {
            fprintf(stderr, "UUID not %d characters long.\n", UUID_STR_LEN);
            return 1;
        }

        params->uuid_hex = args_info->inputs[2];

        if(args_info->inputs_num == 4) {
            if(EVP_CIPHER_iv_length(evp_cipher) == 0) {
                fprintf(stderr, "The chosen cipher doesn't require an IV.\n");
                return 1;
            }
            if(strlen(args_info->inputs[3]) != EVP_CIPHER_iv_length(evp_cipher) * 2) {
                fprintf(stderr,"Length of IV doesn't match the chosen cipher's required IV"
                               " length match\n");
                return 1;
            }

            params->iv_hex = args_info->inputs[3];
        }
    }
    else if(algo->mode == MODE_EC) {
        if(args_info->inputs_num != 2) {
            fprintf(stderr, "%s\n", gengetopt_args_info_usage);
            return 1;
        }

        EC_GROUP *group = EC_GROUP_new_by_curve_name(algo->nid);
        if(group == NULL) {
            fprintf(stderr, "EC_GROUP_new_by_curve_name failed.\n");
            return 1;
        }
        size_t order_len = (EC_GROUP_order_bits(group) + 7) / 8;
        size_t comp_len = order_len + 1;
        size_t uncomp_len = (order_len * 2) + 1;
        if(strlen(args_info->inputs[1]) != comp_len * 2 && \
                strlen(args_info->inputs[1]) != uncomp_len * 2) {
            fprintf(stderr, "CLIENT_PUB_KEY not %zu nor %zu bytes for %s\n",
                       comp_len, uncomp_len, algo->full_name);
            return 1;
        }
        EC_GROUP_free(group);

        params->client_crypto_hex = args_info->inputs[1];
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

    struct params params;
    struct gengetopt_args_info args_info;

    unsigned char host_seed[SEED_SIZE];
    unsigned char client_seed[SEED_SIZE];

    const EVP_CIPHER *evp_cipher;
    unsigned char client_cipher[EVP_MAX_BLOCK_LENGTH];
    unsigned char uuid[UUID_SIZE];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    EC_GROUP *ec_group;
    EC_POINT *client_ec_point;

    int mismatch, ending_mismatch;
    int random_flag, benchmark_flag;
    int all_flag, count_flag, verbose_flag;
    int subseed_length;
    const algo *algo;

    double start_time, duration, key_rate;
    long long int validated_keys = 0;
    int found, subfound;

#ifdef USE_MPI
    mpz_t key_count;
    size_t max_count;
#endif

    memset(&params, 0, sizeof(params));

    // Parse arguments
    if(cmdline_parser(argc, argv, &args_info) || validate_args(&args_info) || \
            parse_params(&params, &args_info)) {
#ifdef USE_MPI
        MPI_Finalize();
#else
        OMP_DESTROY()
#endif

        return ERROR_CODE_FAILURE;
    }

    algo = find_algo(args_info.mode_orig, supported_algos);
    random_flag = args_info.random_flag;
    benchmark_flag = args_info.benchmark_flag;
    all_flag = args_info.all_flag;
    count_flag = args_info.count_flag;
    verbose_flag = args_info.verbose_flag;
    subseed_length = args_info.subkey_arg;

    mismatch = 0;
    ending_mismatch = args_info.subkey_arg;

    // If --fixed option was set, set the validation range to only use the --mismatches value.
    if (args_info.fixed_flag) {
        mismatch = args_info.mismatches_arg;
        ending_mismatch = args_info.mismatches_arg;
    }
    // If --mismatches is set and non-negative, set the ending_mismatch to its value.
    else if(args_info.mismatches_arg >= 0) {
        ending_mismatch = args_info.mismatches_arg;
    }

#ifndef USE_MPI
    if (args_info.threads_arg > 0) {
        omp_set_num_threads(args_info.threads_arg);
    }

    // omp_get_num_threads() must be called in a parallel region, but
    // ensure that only one thread calls it
#pragma omp parallel default(none) shared(numcores)
#pragma omp single
    numcores = omp_get_num_threads();
#endif

    // Memory alloc/init
    if(algo->mode == MODE_CIPHER) {
        evp_cipher = EVP_get_cipherbynid(algo->nid);
    }
    else if(algo->mode == MODE_EC) {
        if((ec_group = EC_GROUP_new_by_curve_name(algo->nid)) == NULL) {
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

    if (random_flag || benchmark_flag) {
#ifdef USE_MPI
        if(my_rank == 0) {
#endif
            gmp_randstate_t randstate;

            // Set the gmp prng algorithm and set a seed based on the current time
            gmp_randinit_default(randstate);
            gmp_randseed_ui(randstate, (unsigned long) time(NULL));

            get_random_seed(host_seed, SEED_SIZE, randstate);
            get_random_corrupted_seed(client_seed, host_seed, args_info.mismatches_arg, SEED_SIZE,
                                      subseed_length, randstate, benchmark_flag,
#ifdef USE_MPI
                                      nprocs);
#else
                                      numcores);
#endif

            if(algo->mode == MODE_CIPHER && EVP_CIPHER_iv_length(evp_cipher) > 0) {
                get_random_seed(iv, EVP_CIPHER_iv_length(evp_cipher), randstate);
            }

            if(algo->mode == MODE_CIPHER) {
                get_random_seed(uuid, AES_BLOCK_SIZE, randstate);

                if(evp_encrypt(client_cipher, NULL, evp_cipher, client_seed, uuid, UUID_SIZE,
                               iv)) {
                    fprintf(stderr, "ERROR: Initial encryption failed.\nOpenSSL Error: %s\n",
                            ERR_error_string(ERR_get_error(), NULL));

                    OMP_DESTROY()

                    return ERROR_CODE_FAILURE;
                }
            }
            else if (algo->mode == MODE_EC) {
                if(get_ec_public_key(client_ec_point, NULL, ec_group, client_seed, SEED_SIZE)) {
                    EC_POINT_free(client_ec_point);
                    EC_GROUP_free(ec_group);

                    OMP_DESTROY()

                    return ERROR_CODE_FAILURE;
                }
            }

            // Clear GMP PRNG
            gmp_randclear(randstate);
#ifdef USE_MPI
        }

        // Broadcast all of the relevant variable to every rank
        MPI_Bcast(host_seed, SEED_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        MPI_Bcast(client_seed, SEED_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

        if(algo->mode == MODE_CIPHER) {
            MPI_Bcast(client_cipher, AES_BLOCK_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
            MPI_Bcast(uuid, UUID_SIZE, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
        }
        else if(algo->mode == MODE_EC) {
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
        int parse_status = parse_hex_handler(host_seed, params.seed_hex);

        if(!parse_status) {
            if(algo->mode == MODE_CIPHER) {
                parse_status = parse_hex_handler(client_cipher, params.client_crypto_hex);

                if(!parse_status && uuid_parse(uuid, params.uuid_hex)) {
                    fprintf(stderr, "ERROR: UUID not in canonical form.\n");
                    parse_status = 1;
                }

                if (!parse_status && params.iv_hex != NULL) {
                    parse_status = parse_hex_handler(iv, params.iv_hex);
                }
            }
            else if (algo->mode == MODE_EC) {
                if (EC_POINT_hex2point(ec_group, params.client_crypto_hex,
                                       client_ec_point, NULL) == NULL) {
                    fprintf(stderr, "ERROR: EC_POINT_hex2point failed.\nOpenSSL Error: %s\n",
                            ERR_error_string(ERR_get_error(), NULL));
                    parse_status = 1;
                }
            }
        }

        if(parse_status) {
            if(algo->mode == MODE_EC) {
                EC_POINT_free(client_ec_point);
                EC_GROUP_free(ec_group);
            }
            OMP_DESTROY()

            return ERROR_CODE_FAILURE;
        }
    }

    if (verbose_flag
#ifdef USE_MPI
        && my_rank == 0
#endif
    ) {
        fprintf(stderr, "INFO: Using HOST_SEED:                  ");
        fprint_hex(stderr, host_seed, SEED_SIZE);
        fprintf(stderr, "\n");

        if(random_flag || benchmark_flag) {
            fprintf(stderr, "INFO: Using CLIENT_SEED (%d mismatches): ",
                    args_info.mismatches_arg);
            fprint_hex(stderr, client_seed, SEED_SIZE);
            fprintf(stderr, "\n");
        }

        if(algo->mode == MODE_CIPHER) {
            char uuid_str[UUID_STR_LEN + 1];

            fprintf(stderr, "INFO: Using %s CLIENT_CIPHER: %*s", algo->full_name,
                    (int)strlen(algo->full_name) - 4, "");
            fprint_hex(stderr, client_cipher, AES_BLOCK_SIZE);
            fprintf(stderr, "\n");

            // Convert the uuid to a string for printing
            fprintf(stderr, "INFO: Using UUID:                       ");
            uuid_unparse(uuid_str, uuid);
            fprintf(stderr, "%s\n", uuid_str);

            if(EVP_CIPHER_iv_length(evp_cipher) > 0) {
                fprintf(stderr, "INFO: Using IV:                         ");
                fprint_hex(stderr, iv, EVP_CIPHER_iv_length(evp_cipher));
                fprintf(stderr, "\n");
            }
        }
        else if(algo->mode == MODE_EC) {
            if(random_flag || benchmark_flag) {
                fprintf(stderr, "INFO: Using %s HOST_PUB_KEY:%*s",
                        algo->full_name, (int)strlen(algo->full_name) - 4, "");
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

            fprintf(stderr, "INFO: Using %s CLIENT_PUB_KEY:%*s", algo->full_name,
                    (int)strlen(algo->full_name) - 6, "");
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

        fflush(stderr);
    }

    found = 0;

#ifdef USE_MPI
    mpz_init(key_count);

    start_time = MPI_Wtime();
#else
    start_time = omp_get_wtime();
#endif

    for (; mismatch <= ending_mismatch && !found; mismatch++) {
        if(verbose_flag
#ifdef USE_MPI
            && my_rank == 0
#endif
        ) {
            fprintf(stderr, "INFO: Checking a hamming distance of %d...\n", mismatch);
            fflush(stderr);
        }

#ifndef USE_MPI
#pragma omp parallel default(none) shared(found, host_seed, client_seed, evp_cipher, client_cipher, iv,\
            uuid, ec_group, client_ec_point, mismatch, validated_keys, algo, subseed_length,\
            all_flag, count_flag, verbose_flag)\
            private(subfound)
        {
        long long int sub_validated_keys = 0;
#endif

        int (*crypto_func)(const unsigned char*, void*) = NULL;
        int (*crypto_cmp)(void*) = NULL;

        void *v_args = NULL;

        subfound = 0;

        if(algo->mode == MODE_CIPHER) {
#ifndef ALWAYS_EVP_AES
            // Use a custom implementation for improved speed
            if(algo->nid == NID_aes_256_ecb) {
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

            v_args = cipher_validator_create(evp_cipher, client_cipher, uuid, UUID_SIZE,
                                             EVP_CIPHER_iv_length(evp_cipher) > 0 ? iv : NULL);
        }
        else if(algo->mode == MODE_EC) {
            crypto_func = ec_crypto_func;
            crypto_cmp = ec_crypto_cmp;
            v_args = ec_validator_create(ec_group, client_ec_point);
        }

#ifdef USE_MPI
        mpz_bin_uiui(key_count, subseed_length, mismatch);

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
                              mismatch, subseed_length);

            subfound = find_matching_seed(client_seed, host_seed, first_perm, last_perm,
                                          all_flag,
                                          count_flag ? &validated_keys : NULL,
                                          &found, verbose_flag, my_rank, max_count,
                                          crypto_func, crypto_cmp, v_args);

            mpz_clears(first_perm, last_perm, NULL);

            if (subfound < 0) {
                // Cleanup
                mpz_clear(key_count);

                if(algo->mode == MODE_CIPHER) {
                    if(algo->nid != NID_aes_256_ecb) {
                        cipher_validator_destroy(v_args);
                    }
                }
                else if(algo->mode == MODE_EC) {
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
                          subseed_length);

            subfound = find_matching_seed(client_seed, host_seed, first_perm, last_perm,
                                          all_flag,
                                          count_flag ? &sub_validated_keys : NULL,
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

            if(algo->mode == MODE_CIPHER) {
                cipher_validator_destroy(v_args);
            }
            else if(algo->mode == MODE_EC) {
                ec_validator_destroy(v_args);
            }
#ifndef USE_MPI
        }
#endif
    }

    if(algo->mode == MODE_EC) {
        EC_POINT_free(client_ec_point);
        EC_GROUP_free(ec_group);
    }

#ifdef USE_MPI
    if((mismatch <= ending_mismatch) && !(all_flag) && subfound == 0 && !found) {
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

    if(my_rank == 0 && verbose_flag) {
        fprintf(stderr, "INFO: Max Clock time: %f s\n", duration);
    }

    if(count_flag) {
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

    if(verbose_flag) {
        fprintf(stderr, "INFO: Clock time: %f s\n", duration);
        fprintf(stderr, "INFO: Found: %d\n", found);
    }

    if(count_flag) {
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

    return found || algo->mode == MODE_NONE ? ERROR_CODE_FOUND : ERROR_CODE_NOT_FOUND;
#endif
}
