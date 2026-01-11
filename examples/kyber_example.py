"""
Kyber KEM Example

Demonstrates:
- Key generation
- Key serialization (raw and armored)
- Key fingerprints
- Encapsulation and decapsulation
"""

from qcrypto import KyberKEM, key_fingerprint


def main():
    # Create a Kyber768 KEM instance
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    # Key fingerprint for identity verification
    fp = key_fingerprint(keys.public_key)
    print(f"Public key fingerprint: {fp}")

    # Encapsulate: sender creates ciphertext + shared secret
    ct, ss_sender = kem.encapsulate(keys.public_key)
    print(f"Encapsulated shared secret: {ss_sender.hex()[:32]}...")

    # Decapsulate: recipient recovers the same shared secret
    ss_recipient = kem.decapsulate(ct, private_key=keys.private_key)
    print(f"Decapsulated shared secret: {ss_recipient.hex()[:32]}...")

    print(f"Shared secrets match: {ss_sender == ss_recipient}")

    # --- Key Serialization Examples ---

    # Save keys in raw binary format
    kem.save_public_key("kyber_pub.key", encoding="raw")
    kem.save_private_key("kyber_priv.key", encoding="raw")
    print("\nSaved raw keys: kyber_pub.key, kyber_priv.key")

    # Save keys in ASCII-armored format (human-readable)
    kem.save_public_key("kyber_pub.asc", encoding="armor")
    kem.save_private_key("kyber_priv.asc", encoding="armor")
    print("Saved armored keys: kyber_pub.asc, kyber_priv.asc")

    # Load keys back
    pub_loaded = KyberKEM.load_public_key("kyber_pub.asc")
    priv_loaded = KyberKEM.load_private_key("kyber_priv.asc")

    # Verify fingerprint is preserved
    fp_loaded = key_fingerprint(pub_loaded)
    print(f"\nLoaded key fingerprint: {fp_loaded}")
    print(f"Fingerprint matches: {fp == fp_loaded}")


if __name__ == "__main__":
    main()
