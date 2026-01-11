"""
Dilithium Signature Example

Demonstrates:
- Dilithium keypair generation
- Signing and verifying messages
- Key and signature serialization
"""

from qcrypto import DilithiumSig, key_fingerprint
from qcrypto.signatures import (
    save_signature_public_key,
    load_signature_public_key,
    save_signature_private_key,
    load_signature_private_key,
    save_signature,
    load_signature,
)


def main():
    # Create Dilithium signer (Dilithium2, Dilithium3, or Dilithium5)
    sig = DilithiumSig("Dilithium3")
    keys = sig.generate_keypair()

    fp = key_fingerprint(keys.public_key)
    print(f"Dilithium3 public key fingerprint: {fp}")

    # Sign a message
    message = b"This document is authentic."
    signature = sig.sign(keys.secret_key, message)
    print(f"Signature size: {len(signature)} bytes")

    # Verify the signature
    valid = sig.verify(keys.public_key, message, signature)
    print(f"Signature valid: {valid}")

    # Verify with wrong message fails
    tampered = b"This document is NOT authentic."
    invalid = sig.verify(keys.public_key, tampered, signature)
    print(f"Tampered message valid: {invalid}")

    # --- Key Serialization ---
    save_signature_public_key("dilithium.pub", keys.public_key, "Dilithium3", armored=True)
    save_signature_private_key("dilithium.key", keys.secret_key, "Dilithium3", armored=True)
    save_signature("message.sig", signature, "Dilithium3", armored=True)
    print("\nSaved armored keys and signature")

    # Load and verify again
    alg, pk = load_signature_public_key("dilithium.pub")
    _, sig_bytes = load_signature("message.sig")
    valid2 = sig.verify(pk, message, sig_bytes)
    print(f"Loaded signature valid: {valid2}")


if __name__ == "__main__":
    main()
