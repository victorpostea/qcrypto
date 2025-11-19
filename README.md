# qcrypto

**Version: 0.2.1**

`qcrypto` is a lightweight Python library providing simple, Pythonic wrappers around post-quantum cryptography (PQC) algorithms using the official `liboqs-python` bindings from the Open Quantum Safe project.

The library currently includes:

- Kyber Key Encapsulation Mechanism (KEM)
- Dilithium digital signatures
- A hybrid PQC + AES-GCM encryption scheme
- Clean utility classes and exception handling

`qcrypto` is suitable for learning PQC, research, prototyping, and experiments involving quantum-safe primitives.

## Features

### Kyber KEM
- Public/secret key generation
- Encapsulation (ciphertext + shared secret)
- Decapsulation (recover shared secret)
- Supports Kyber512, Kyber768, Kyber1024

### Dilithium Signatures
- Keypair generation
- Message signing
- Signature verification
- Supports Dilithium2, Dilithium3, Dilithium5

### Hybrid PQC + AES Encryption
A simple hybrid model where:
- Kyber encapsulates a symmetric key
- AES-256-GCM encrypts the message
- Result is `(kem_ciphertext, aes_ciphertext)`

## Installation

Requires Python 3.8+.

```
pip install qcrypto
```

This installs `liboqs-python` automatically.

## Usage

Usage examples are available in the `examples/` directory

## Implementation Notes
- Uses `liboqs-python`, which bundles OQS C library implementations.
- Hybrid encryption uses AES-256-GCM.
- Pure Python package, no compiled extensions.
- Modern PEP 621 `src/` layout.

## Changelog

### v0.2.0 — Hybrid API Rewrite, Key Serialization, Ciphertext Format
- Added `encrypt()` and `decrypt()` as the new high-level hybrid PQC API  
- Introduced a single-blob ciphertext format:
  - version byte  
  - algorithm identifier  
  - Kyber ciphertext length  
  - Kyber ciphertext  
  - AES-GCM nonce  
  - AES-GCM ciphertext+tag  
- Added key serialization helpers:
  - `save_public_key()`, `save_private_key()`
  - `KyberKEM.load_public_key()`, `KyberKEM.load_private_key()`
- `decapsulate()` now accepts a private key directly  
- Legacy API (`encrypt_for_recipient`, `decrypt_from_sender`) retained for compatibility  
- Updated example usage and documentation  
- Cleaned internal attribute naming (`private_key` rather than `secret_key`)


## Disclaimer
This library is for educational, experimental, and research use.  
It is not a production security component and has not undergone cryptographic review.

## License
MIT License.

## Resources
- Open Quantum Safe Project: https://openquantumsafe.org
- liboqs-python: https://github.com/open-quantum-safe/liboqs-python
