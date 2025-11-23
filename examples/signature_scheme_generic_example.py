from qcrypto import SignatureScheme

def run_scheme(alg):
    scheme = SignatureScheme(alg)
    keys = scheme.generate_keypair()

    msg = b"generic signature demo"
    sig = scheme.sign(keys.secret_key, msg)
    ok = scheme.verify(keys.public_key, msg, sig)

    print(f"{alg} signature valid:", ok)


def main():
    run_scheme("Falcon-512")
    run_scheme("SPHINCS+-SHA2-128f-simple")
    run_scheme("Dilithium3")   # works too!


if __name__ == "__main__":
    main()
