import hashlib
import secrets
import sys

from util import corrupt_key

SEED_SIZE = 32
SALT_SIZE = 16

if __name__ == "__main__":
    mismatches = int(sys.argv[1])
    is_salt = sys.argv[2] == "True"

    host_seed = secrets.token_bytes(SEED_SIZE)
    client_seed = corrupt_key(host_seed, mismatches)
    salt = secrets.token_bytes(SALT_SIZE) if is_salt else bytes()

    if is_salt:
        print("Salt:         ", salt.hex())
    print("Host Seed:    ", host_seed.hex())
    print("Host Digest:  ", hashlib.sha3_384(host_seed + salt).hexdigest())
    print("Client Seed:  ", client_seed.hex())
    print("Client Digest:", hashlib.sha3_384(client_seed + salt).hexdigest())
