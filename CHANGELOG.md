# rbc_validator Changelog

## v1.0 (May 21, 2021)

### Features

* Added support for the following symmetric keys (ciphers):
  * AES-256-ECB
  * ChaCha20
* Added support for the following public keys:
  * ECC Secp256r1
* Added support for the following hash functions:
  * MD5
  * SHA1
  * SHA224
  * SHA256
  * SHA384
  * SHA512
  * SHA3-224
  * SHA3-256
  * SHA3-384
  * SHA3-512
  * SHAKE128
  * SHAKE256
  * KangarooTwelve
* Added support for the following modes:
  * **Direct**: Pass in a known host seed and known client output to derive the client's seed
  * `--random`: Generate the seed and errors randomly. Useful for benchmarking that models
    uniformly random distributions.
  * `--benchmark`: Generate the seed and errors such that the errors are exactly halfway through a
    core's/rank's workload. Useful for benchmarking but you're short on time or want
    reproducibility.
* Added support for both OpenMP and OpenMPI implementations
* Added the following options:
  * `--all`: Enforces search to continue through an entire Hamming distance's search space even if a
    matching seed is found
  * `--fixed`: _Only_ searches a given Hamming distance's search space (no more nor less)
* Added the ability to choose between OpenSSL vs. a faster custom AES256 implementation using
  `ALWAYS_EVP_AES`. Defaults to the custom implementation
* Added the ability to choose between EVP vs. low level OpenSSL implementation of MD5, SHA1, and
  SHA2 using `ALWAYS_EVP_HASH`. Defaults to the low level implementations.
* Added the ability to choose between OpenSSL vs. XKCP implementations for SHA3 and SHAKE
  using `ALWAYS_EVP_SHA3`. Defaults to OpenSSL implementations. _(Note: Testing has found that the
  OpenSSL tends to be faster than the `generic64`, `SSSE3`, and `AVX` XKCP compilations on Zen 2.
  `AVX2` is about on par. `AVX512` XKCP is significantly faster than OpenSSL on Xeon Skylake
  CPUs.)_
* Added the ability to manually select the architecture to build XKCP against between:
  * `reference`
  * `reference32bits`
  * `compact`
  * `generic32`
  * `generc32lc`
  * `generic64`
  * `generic64lc`
  * `SSSE3`
  * `AVX`
  * `AVX2`
  * `AVX512`
  
  Defaults to `generic64` to maximize compatibility while balancing for basic optimizations.
  