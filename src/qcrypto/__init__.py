"""
qcrypto: Post-quantum cryptography for Python.

Provides:
- Kyber KEM key generation, encapsulation, and decapsulation
- Dilithium digital signatures
- Hybrid PQC + AES-GCM authenticated encryption
- High-level encrypt() and decrypt() using Kyber768 + HKDF + AES-GCM
"""

from .kem import KyberKEM, KyberKeypair
from .signatures import DilithiumSig, DilithiumKeypair
from .hybrid import (
    encrypt,
    decrypt,
    encrypt_for_recipient,
    decrypt_from_sender,
)

__all__ = [
    "KyberKEM",
    "KyberKeypair",
    "DilithiumSig",
    "DilithiumKeypair",
    "encrypt",
    "decrypt",
    # legacy v0.1 API
    "encrypt_for_recipient",
    "decrypt_from_sender",
]
