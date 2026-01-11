"""
Classic McEliece KEM Example

Demonstrates:
- Classic McEliece key generation (note: large keys!)
- Encapsulation and decapsulation
"""

from qcrypto import ClassicMcElieceKEM, key_fingerprint


def main():
    # Classic McEliece has very large keys but small ciphertexts
    # Default: Classic-McEliece-348864 (128-bit security)
    kem = ClassicMcElieceKEM("Classic-McEliece-348864")
    keys = kem.generate_keypair()

    print("Classic-McEliece-348864:")
    print(f"  Public key: {len(keys.public_key):,} bytes")
    print(f"  Private key: {len(keys.private_key):,} bytes")
    print(f"  Fingerprint: {key_fingerprint(keys.public_key)}")

    # Encapsulate
    ct, ss_sender = kem.encapsulate(keys.public_key)
    print(f"  Ciphertext: {len(ct)} bytes")
    print(f"  Shared secret: {len(ss_sender)} bytes")

    # Decapsulate
    ss_recipient = kem.decapsulate(ct, private_key=keys.private_key)

    print(f"  Shared secrets match: {ss_sender == ss_recipient}")

    # Note: Other parameter sets available:
    # Classic-McEliece-460896, Classic-McEliece-6688128, Classic-McEliece-8192128
    # (with 'f' suffix variants for faster key generation)


if __name__ == "__main__":
    main()
