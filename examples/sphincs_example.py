"""
SPHINCS+ Signature Example

Demonstrates:
- SPHINCS+ hash-based signatures
- Different parameter sets (SHA2 vs SHAKE, fast vs small)
"""

from qcrypto import SphincsSig, key_fingerprint


def main():
    # SPHINCS+-SHA2-128f-simple (fast variant)
    print("SPHINCS+-SHA2-128f-simple:")
    sig_fast = SphincsSig("SPHINCS+-SHA2-128f-simple")
    keys_fast = sig_fast.generate_keypair()

    print(f"  Public key: {len(keys_fast.public_key)} bytes")
    print(f"  Secret key: {len(keys_fast.secret_key)} bytes")
    print(f"  Fingerprint: {key_fingerprint(keys_fast.public_key)}")

    message = b"SPHINCS+ signature demo"
    signature_fast = sig_fast.sign(keys_fast.secret_key, message)
    print(f"  Signature: {len(signature_fast)} bytes")

    valid_fast = sig_fast.verify(keys_fast.public_key, message, signature_fast)
    print(f"  Valid: {valid_fast}")

    # SPHINCS+-SHA2-128s-simple (small signatures, slower)
    print("\nSPHINCS+-SHA2-128s-simple:")
    sig_small = SphincsSig("SPHINCS+-SHA2-128s-simple")
    keys_small = sig_small.generate_keypair()

    print(f"  Public key: {len(keys_small.public_key)} bytes")
    print(f"  Secret key: {len(keys_small.secret_key)} bytes")

    signature_small = sig_small.sign(keys_small.secret_key, message)
    print(f"  Signature: {len(signature_small)} bytes (smaller than fast variant)")

    valid_small = sig_small.verify(keys_small.public_key, message, signature_small)
    print(f"  Valid: {valid_small}")


if __name__ == "__main__":
    main()
