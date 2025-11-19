from qcrypto import KyberKEM, encrypt, decrypt


def main():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    plaintext = b"super secure pqc message"

    # New v0.2 single-blob encryption
    ciphertext = encrypt(keys.public_key, plaintext)

    recovered = decrypt(keys.private_key, ciphertext)

    print("Hybrid recovered == plaintext:", recovered == plaintext)


if __name__ == "__main__":
    main()
