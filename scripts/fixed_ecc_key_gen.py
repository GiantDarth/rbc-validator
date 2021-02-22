import sys

from Crypto.PublicKey import ECC

from config import EC_CURVE
from util import corrupt_key, get_ec_private_key_bytes, get_ec_public_key_bytes


if __name__ == "__main__":
    mismatches = int(sys.argv[1])

    host_priv_key = ECC.generate(curve=EC_CURVE)
    host_priv_key_bytes = get_ec_private_key_bytes(host_priv_key)
    host_pub_key_bytes = get_ec_public_key_bytes(host_priv_key, compress=False)

    client_priv_key_bytes = corrupt_key(host_priv_key_bytes, mismatches)
    client_priv_key = ECC.construct(curve=EC_CURVE, d=int.from_bytes(client_priv_key_bytes, "big"))
    client_pub_key_bytes = get_ec_public_key_bytes(client_priv_key, compress=False)

    print("EC Host Private Key:     ", host_priv_key_bytes.hex())
    print("EC Host Public Key:      ", host_pub_key_bytes.hex())
    print("EC Corrupted Private Key:", client_priv_key_bytes.hex())
    print("EC Corrupted Public Key: ", client_pub_key_bytes.hex())
