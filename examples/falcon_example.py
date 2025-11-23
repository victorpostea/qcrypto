from qcrypto import FalconSig

def main():
    sig = FalconSig("Falcon-512")   # or "Falcon-1024"
    keys = sig.generate_keypair()

    message = b"falcon signature demo"

    signature = sig.sign(keys.secret_key, message)
    ok = sig.verify(keys.public_key, message, signature)

    print("Falcon signature valid:", ok)


if __name__ == "__main__":
    main()
