import sys

from Crypto.PublicKey import ECC

ECC_CURVE = "secp256r1"

if __name__ == "__main__":
    priv_key = bytes.fromhex(sys.argv[1])

    ecc_key = ECC.construct(curve=ECC_CURVE, d=int.from_bytes(priv_key, "big"))

    print("ECC Private Key:", get_ec_public_key_bytes().hex())
    print("ECC Public Key:", (ecc_key.pointQ.x.to_bytes(32, "big") + ecc_key.pointQ.y.to_bytes(32)).hex())
