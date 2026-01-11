"""
File Encryption Example

Demonstrates:
- Encrypting and decrypting files with streaming I/O
- Works with files of any size without loading into memory
"""

import os
import tempfile
from qcrypto import KyberKEM, encrypt_file, decrypt_file, key_fingerprint


def main():
    # Generate keypair
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    fp = key_fingerprint(keys.public_key)
    print(f"Using key: {fp}")

    # Create a test file
    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = os.path.join(tmpdir, "secret.txt")
        encrypted_path = os.path.join(tmpdir, "secret.txt.enc")
        decrypted_path = os.path.join(tmpdir, "secret.decrypted.txt")

        # Write test data
        test_data = b"This is sensitive information.\n" * 100
        with open(input_path, "wb") as f:
            f.write(test_data)
        print(f"\nCreated test file: {len(test_data)} bytes")

        # Encrypt the file
        encrypt_file(
            public_key=keys.public_key,
            input_path=input_path,
            output_path=encrypted_path,
        )
        encrypted_size = os.path.getsize(encrypted_path)
        print(f"Encrypted file: {encrypted_size} bytes")

        # Decrypt the file
        decrypt_file(
            private_key=keys.private_key,
            input_path=encrypted_path,
            output_path=decrypted_path,
        )

        # Verify
        with open(decrypted_path, "rb") as f:
            recovered = f.read()

        print(f"Decrypted file: {len(recovered)} bytes")
        print(f"Files match: {recovered == test_data}")


if __name__ == "__main__":
    main()
