import argparse
import secrets
import uuid
import subprocess
import re
import math
import hashlib
import sys
from pathlib import Path, PurePosixPath
from typing import Tuple, Optional

from Crypto.Cipher import AES, ChaCha20
from Crypto.PublicKey import ECC
from K12 import KangarooTwelve

from config import (SEED_SIZE, CHACHA20_OPENSSL_NONCE_SIZE, CHACHA20_NONCE_SIZE, EC_CURVE, KANG12_SIZE)
from util import corrupt_key, get_ec_public_key_bytes

hash_modes = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384",
              "sha3-512"}


def simulate_fragmentation(rbc_path: Path, mismatches: int, seed_size: int, subseed_size: int,
                           mode: str, timeout: Optional[float] = None,
                           cutoff: bool = True, threads: int = 0) -> Tuple[float, int]:
    user_id = uuid.uuid4()
    host_seed = secrets.token_bytes(seed_size)
    client_seed = corrupt_key(host_seed, mismatches)

    host_subseeds = [bytearray(host_seed[index:index + subseed_size])
                     for index in range(0, len(host_seed), subseed_size)]
    client_subseeds = [bytearray(client_seed[index:index + subseed_size])
                       for index in range(0, len(client_seed), subseed_size)]
    args = []

    for client_subseed in client_subseeds:
        nonce = secrets.token_bytes(len(host_seed) - subseed_size)
        client_subkey = client_subseed + nonce

        if mode == "aes":
            aes = AES.new(client_subkey, AES.MODE_ECB)
            subargs = [aes.encrypt(user_id.bytes).hex(), str(user_id)]
        elif mode == "chacha20":
            chacha20_nonce = secrets.token_bytes(CHACHA20_NONCE_SIZE)
            chacha20 = ChaCha20.new(key=client_subkey, nonce=chacha20_nonce)
            client_key = chacha20.encrypt(user_id.bytes)

            iv = chacha20.nonce
            iv = bytes(CHACHA20_OPENSSL_NONCE_SIZE - len(iv)) + iv

            subargs = [client_key.hex(), user_id.hex, iv.hex()]
        elif mode == "ecc":
            client_priv_key = ECC.construct(curve=EC_CURVE, d=int.from_bytes(client_subkey, "big"))
            subargs = [get_ec_public_key_bytes(client_priv_key, compress=False).hex()]
        elif mode in hash_modes:
            h = hashlib.new(mode.replace('-', '_'))
            h.update(client_subseed)
            subargs = [h.hexdigest()]
        elif mode == "kang12":
            subargs = [KangarooTwelve(client_subseed, b'', KANG12_SIZE).hex()]
        else:
            ValueError(f"Error: Mode '{mode}' is not recognized.")
            sys.exit(1)

        args.append(subargs)

    duration = 0
    key_count = 0

    for subkey, subargs in zip(host_subseeds, args):
        # Call rbc_validator over wsl with the UUID, the full server subkey, the client cipher, and only
        # the necessary subkey size set
        # Only extract the stderr output in verbose mode to get the actual time taken searching in text
        # mode, and make sure to check if the return code was zero or not
        env_args = []

        rbc_path_abs = rbc_path.resolve()

        if sys.platform == "win32":
            env_args.append("wsl")
            rbc_path_abs = PurePosixPath("/mnt", rbc_path_abs.drive[:-1].lower(),
                                         *rbc_path_abs.parts[1:])

        env_args += [
            rbc_path_abs.as_posix(),
            f"--mode={mode}",
            f"--subkey={subseed_size * 8}",
            f"--threads={threads}",
            "-v",
            "-c"
        ]

        if not cutoff:
            env_args.append("-a")

        env_args += [
            subkey.hex(),
            *subargs
        ]

        try:
            validator_proc = subprocess.run(env_args,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                            universal_newlines=True, check=True,
                                            timeout=None if timeout is None else timeout - duration)
        except subprocess.TimeoutExpired:
            return float("inf"), key_count

        lines = [line for line in validator_proc.stderr.split("\n")]
        # Get the first line such that "Clock" is contained within it.
        clock_line = next(line for line in lines if re.search(r"Clock", line))
        count_line = next(line for line in lines if re.search(r"searched", line))
        # Get only the decimal output (in seconds) and increment duration by its value
        duration += float(clock_line.split(" ")[3])
        key_count += int(count_line.split(" ")[3])

        print(env_args)

        print(subkey.hex())
        for subarg in subargs:
            print(subarg)
        print()
        print(clock_line)
        print(count_line)
        print()

    return duration, key_count


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""
Simulate doing fragmentation by generating a random key, randomly corrupting it, then splitting it into
even chunks to be fed into rbc_validator.
""",
        prog="frag_sim")
    parser.add_argument("path", type=Path,
                        help="A path to a valid executable of rbc_validator or rbc_validator_mpi.")
    parser.add_argument("--mode", type=str, required=True,
                        help="Which algorithm to feed into rbc_validator.")
    parser.add_argument("-m", "--mismatches", type=int, required=True,
                        help="How many mismatches to corrupt the host key by.")
    parser.add_argument("-k", type=int, default=1,
                        choices=[2**i for i in range(int(math.log2(SEED_SIZE)) + 1)],
                        help="How many times to fragment the seed by. Defaults to 1.")
    parser.add_argument("-t", "--threads", type=int, default=0,
                        help="How many threads to use. Defaults to 0.")
    parser.add_argument("-a", "--all", action="store_true",
                        help="Whether to ignore early cutoff or not.")

    args = parser.parse_args()

    rbc_path = args.path
    mode = args.mode
    mismatches = args.mismatches
    subseed_count = args.k
    threads = args.threads
    cutoff = not args.all

    duration, key_count = simulate_fragmentation(rbc_path, mismatches, SEED_SIZE,
                                                 SEED_SIZE // subseed_count, mode, cutoff=cutoff,
                                                 threads=threads)

    print(f"{duration},{key_count},{key_count / duration}")


if __name__ == "__main__":
    main()
