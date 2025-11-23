from qcrypto import SphincsSig

def main():
    sig = SphincsSig("SPHINCS+-SHA2-128f-simple")
    keys = sig.generate_keypair()

    message = b"sphincs+ signature demo"

    signature = sig.sign(keys.secret_key, message)
    ok = sig.verify(keys.public_key, message, signature)

    print("SPHINCS+ signature valid:", ok)


if __name__ == "__main__":
    main()
