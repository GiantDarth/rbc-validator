[![CI](https://github.com/GiantDarth/rbc_validator/actions/workflows/ci.yml/badge.svg)](https://github.com/GiantDarth/rbc_validator/actions/workflows/ci.yml)
[![License](https://img.shields.io/github/license/GiantDarth/rbc_validator)](https://opensource.org/licenses/Apache-2.0)

# rbc_validator

Primary and Auxiliary Authors:
* Christopher R. Philabaum  
* Christopher B. Coffey  
* Duane Booher 

`rbc_validator` is a tool suite written as real-world implementations demonstrating
***RBC (Response-based Cryptography)***, both as a drop-in tool and as a benchmark set.
This solution does _not_ provide a real-world means of generating the disparate server-client
key pairs that need to be corrected (e.g. noisy sources, PUFs, etc.). Instead, the benchmark
functionality uses either pseudo-random number generation rather than direct true-random number
generation, or a targeted and known constant work by selectively choosing the "halfway point"
of a core or rank's workload.

## Requirements

### Hardware

The codebase relies on **SSE**, **AES-NI**, and support for _x86 Intrinsics_ `<x86intrin.h>`
(i.e., GCC 4.5+).

### Supported OSes

* Linux (64-bit)
* MacOS X Mojave or Later
* Windows 10 x64 (MSYS2 MinGW-w64)

### Dependencies

#### Linux

If on Debian-based distributions, the following command can be used to install all the requirements:
```bash
sudo apt-get install libomp-dev libopenmpi-dev openmpi-bin libgmp-dev libssl-dev
```

For other distributions, equivalents for _OpenMP (dev)_, _OpenMPI (bin, dev)_, _GMP (dev)_, and
_OpenSSL (dev)_ should be installed.

#### macOS

macOS implementations have been compiled and tested using Github Actions. This was done using Homebrew,
alongside Xcode. By default, MPI support is disabled on macoS, but can be manually enabled through
`-D MPI_ENABLED=On` in CMake and installing `open-mpi` in Homebrew.

This can be replicated by using the following command:
```zsh
brew install libomp gmp openssl@1.1
```

#### Windows 10 x64 (MSYS2 MinGW-w64)

Windows 10 x64 (MSYS MinGW-w64) implementations have been compiled and tested using Github Actions. This
was done using MSYS2. By default, MPI support is disabled on Windows and there's no clear path to get it
working.

This can be replicated by using the following commands:

First install [MSYS2](https://www.msys2.org/#installation) following the guide _verbatim_.
Then, open in MSYS MinGW 64-bit:
```bash
pacman -S --needed mingw-w64-x86_64-cmake gmp-devel openssl-devel
```

## Install

_rbc_validator_ uses CMake to best support cross-platform toolchains as much as possible. Windows is only
officially supported through MSYS2.

1. `mkdir build`
2. `cd build`
3. Either `ccmake ..` or `cmake ..` without curses (or `cmake -G "MSYS Makefiles" ..` for MSYS2).
4. `make`
5.
    1. Linux, macOS: `make install` (if you want to install to `/usr/local`)
    2. Windows: `./scripts/deploy_msys.sh` copies `rbc_validator` and the relevant DLL's to `dist/win_x64`

## Commands

All cryptographic algorithms are selected at runtime using the `--mode=` option, with the program being
split between an OpenMP implementation and an OpenMPI implementations. The _OpenMP_ implementations are
designed for **single machine** use, whereas the _OpenMPI_ ones target HPC platforms.

* `rbc_validator ...` (OpenMP)
* `mpirun rbc_validator_mpi ...` (MPI)

There are currently 4 algorithms supported:

* `rbc_validator --mode=none` (None, Key iteration only)
* `rbc_validator --mode=aes` (AES256)
* `rbc_validator --mode=chacha20` (ChaCha20)
* `rbc_validator --mode=ecc` (ECC Secp256r1)

Some auxiliary commands also exist for testing the AES-256, ChaCha20, and ECC-Secp256r1 implementations
against target keys and their associated ciphers:

* `aes256_test`
* `cipher_test`
* `ecc_test`

Finally, there exists a few Python scripts to generate some test data, as well as utility
functions.

## Usage

### Modes

#### Direct / Default

This is the default behavior of the main commands. Rather than as a tool for benchmarking,
"direct" mode requires that:

**None:**
1. The original server key

**AES:**
1. The original server key
2. The (potentially) corrupted client cipher
3. A shared message, in this case a 16 byte UUID

**ChaCha20:**
1. The original server key
2. The (potentially) corrupted client cipher
3. A shared message, in this case a 16 byte UUID
4. A 16 byte IV (a 12 byte nonce prepended with 4 bytes of 0's)

**ECC:**
1. The original server private key
2. The (potentially) corrupted client public key

#### Random

Instead of giving the above parameters, the program will simulate the corruption by first 
generating a random server key, corrupting it uniformly randomly by the given _mismatches_,
and either generating the disparate ciphers (AES), or disparate public-private key pairs (ECC).

#### Benchmark

Since the range of possible steps a core / rank might need to take ranges extremely wildly
between _0_ and _256 choose_ m, getting useful benchmark is limited by the amount of runs
it would take to get a strong statistical average. This is compounded by the fact that as
_mismatches_ goes up, the time taken is exponential no matter the amount of compute power
thrown at it.

For this reason, _Benchmark mode_ was made. This made behaves similarly to _Random mode_,
but instead of uniformly randomly choosing the location of the mismatches, it uniformly
randomly chooses the core / rank. Then, whichever is chosen, the location of the mismatches
is strategically chosen to be exactly half of the core's / rank's sequentially load.

### Arguments

All the main commands have (mostly) the same arguments:

* `--usage`: An auto-generated simple usage message made by Argp, which is the same if an
invalid argument is is used.
* `-?, --help`: The main source of information on how to use each command, the arguments list,
their use, default values, and their ranges.
* `--mode=[none,aes,chacha20,ecc]`: The only required option; necessary to decide which cryptographic
  function to use.
* `-m, --mismatches=value`: Give the maximum range of hamming distance / errors to test up to
and including. If not given, then the maximum range is the size of the key in bits.
* `-a, --all`: Ignore any early exit method and have each core / rank carry on through its
workload exhaustively.
* `-f, --fixed`: Only test the given _m_, rather than doing the more realistic checks of
_0, 1, 2, ..., m_.
* `-s, --subkey=value`: The size (in bits) of the key fragment / subkey if using key
fragmentation. Only up to the first _s_ bits will be manipulated.
* `-b, --benchmark`: Forcefully pick the corrupted key to be exactly halfway through a
randomly chosen core's / rank's workload. Mutually exclusive with default and `-r`/`--random`
mode.
* `-r, --random`: Randomly pick the corrupted key along a "number line" from _0_ to
_256 choose m_.
* `-c, --count`: Count each corrupted key generated and tested and display at the end.
* `-v, --verbose`: Produce verbose and benchmarking output to _stderr_. Otherwise, only the
found key is printed to _stdout_.
* `-V, --version`: Print the program version.

The OpenMP implementations also allow direct control of the thread count used:

* `-t, --threads=count`: The number of the threads to use, which defaults to the number of
threads reported on the machine.
