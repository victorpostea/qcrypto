from qcrypto import DilithiumSig

def main():
    sig = DilithiumSig("Dilithium3")
    keys = sig.generate_keypair()

    msg = b"test message"
    signature = sig.sign(keys.secret_key, msg)
    ok = sig.verify(keys.public_key, msg, signature)

    print("Dilithium signature valid:", ok)

if __name__ == "__main__":
    main()
