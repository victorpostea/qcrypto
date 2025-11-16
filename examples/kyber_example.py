from qcrypto import KyberKEM

def main():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    ct, ss1 = kem.encapsulate(keys.public_key)
    ss2 = kem.decapsulate(ct)

    print("Kyber shared secret match:", ss1 == ss2)

if __name__ == "__main__":
    main()