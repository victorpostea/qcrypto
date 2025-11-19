from qcrypto import KyberKEM

def main():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    # You can also choose to save then load keys:
    # kem.save_private_key()
    # kem.save_public_key()
    
    # then to use from here on out
    # pub_key = kem.load_private_key()
    # priv_key = kem.load_public_key()

    ct, ss1 = kem.encapsulate(keys.public_key)
    ss2 = kem.decapsulate(ct)

    print("Kyber shared secret match:", ss1 == ss2)

if __name__ == "__main__":
    main()