from qcrypto import KyberKEM, encrypt_for_recipient, decrypt_from_sender

def main():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    plaintext = b"super secure pqc message"
    kem_ct, aes_blob = encrypt_for_recipient(keys.public_key, plaintext)
    out = decrypt_from_sender(keys, kem_ct, aes_blob)

    print("Hybrid recovered == plaintext:", out == plaintext)

if __name__ == "__main__":
    main()
