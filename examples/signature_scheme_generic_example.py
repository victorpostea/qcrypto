"""
Generic SignatureScheme Example

Demonstrates:
- Using SignatureScheme with any liboqs signature algorithm
- Algorithm-agnostic signature code
"""

from qcrypto import SignatureScheme, key_fingerprint


def demo_scheme(alg: str):
    """Run sign/verify with any liboqs signature algorithm."""
    scheme = SignatureScheme(alg)
    keys = scheme.generate_keypair()

    fp = key_fingerprint(keys.public_key)

    message = b"Generic signature demo message"
    signature = scheme.sign(keys.secret_key, message)
    valid = scheme.verify(keys.public_key, message, signature)

    print(f"{alg}:")
    print(f"  Fingerprint: {fp}")
    print(f"  Public key: {len(keys.public_key)} bytes")
    print(f"  Signature: {len(signature)} bytes")
    print(f"  Valid: {valid}")
    print()


def main():
    # SignatureScheme works with any liboqs algorithm string
    demo_scheme("Dilithium2")
    demo_scheme("Dilithium3")
    demo_scheme("Falcon-512")
    demo_scheme("SPHINCS+-SHA2-128f-simple")


if __name__ == "__main__":
    main()
