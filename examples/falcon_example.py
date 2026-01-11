"""
Falcon Signature Example

Demonstrates:
- Falcon-512 and Falcon-1024 signatures
- Compact signature sizes compared to other PQC schemes
"""

from qcrypto import FalconSig, key_fingerprint


def main():
    # Falcon-512 (smaller, faster)
    sig512 = FalconSig("Falcon-512")
    keys512 = sig512.generate_keypair()

    print("Falcon-512:")
    print(f"  Public key: {len(keys512.public_key)} bytes")
    print(f"  Secret key: {len(keys512.secret_key)} bytes")
    print(f"  Fingerprint: {key_fingerprint(keys512.public_key)}")

    message = b"Falcon signature demo"
    signature512 = sig512.sign(keys512.secret_key, message)
    print(f"  Signature: {len(signature512)} bytes")

    valid512 = sig512.verify(keys512.public_key, message, signature512)
    print(f"  Valid: {valid512}")

    # Falcon-1024 (higher security)
    print("\nFalcon-1024:")
    sig1024 = FalconSig("Falcon-1024")
    keys1024 = sig1024.generate_keypair()

    print(f"  Public key: {len(keys1024.public_key)} bytes")
    print(f"  Secret key: {len(keys1024.secret_key)} bytes")
    print(f"  Fingerprint: {key_fingerprint(keys1024.public_key)}")

    signature1024 = sig1024.sign(keys1024.secret_key, message)
    print(f"  Signature: {len(signature1024)} bytes")

    valid1024 = sig1024.verify(keys1024.public_key, message, signature1024)
    print(f"  Valid: {valid1024}")


if __name__ == "__main__":
    main()
