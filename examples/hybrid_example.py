"""
Hybrid Encryption Example

Demonstrates:
- High-level encrypt() and decrypt() API
- Armored message encoding for copy/paste workflows
- Integration with key fingerprints
"""

from qcrypto import (
    KyberKEM,
    encrypt,
    decrypt,
    encrypt_message_armored,
    decrypt_message_armored,
    key_fingerprint,
)


def main():
    # Generate keypair
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    fp = key_fingerprint(keys.public_key)
    print(f"Encrypting for key: {fp}")

    plaintext = b"Hello, post-quantum world!"

    # --- Binary ciphertext ---
    ciphertext = encrypt(keys.public_key, plaintext)
    print(f"\nBinary ciphertext size: {len(ciphertext)} bytes")

    recovered = decrypt(keys.private_key, ciphertext)
    print(f"Decrypted: {recovered.decode()}")
    print(f"Round-trip OK: {recovered == plaintext}")

    # --- Armored ciphertext (for email, chat, etc.) ---
    armored = encrypt_message_armored(keys.public_key, plaintext)
    print("\n--- Armored Message ---")
    print(armored)

    recovered_armored = decrypt_message_armored(keys.private_key, armored)
    print(f"Armored round-trip OK: {recovered_armored == plaintext}")


if __name__ == "__main__":
    main()
