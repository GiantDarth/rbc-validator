import sys
import secrets
import uuid

from Crypto.PublicKey import ECC

ECC_CURVE = "secp256r1"

if __name__ == "__main__":
    priv_key = bytes.fromhex(sys.argv[1])

    ecc_key = ECC.construct(curve=ECC_CURVE, d=int.from_bytes(priv_key, byteorder='big', signed=False))

    print("ECC Private Key:", priv_key.hex())
    print("ECC Public Key:", (ecc_key.pointQ.x.to_bytes(32) + ecc_key.pointQ.y.to_bytes(32)).hex())
