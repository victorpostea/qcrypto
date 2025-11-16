"""
qcrypto: Post-quantum cryptography for Python.

Provides:
- Kyber KEM key generation, encapsulation, and decapsulation
- Dilithium digital signatures
- Hybrid PQC + AES-GCM authenticated encryption
"""

from .kem import KyberKEM, KyberKeypair
from .signatures import DilithiumSig, DilithiumKeypair
from .hybrid import encrypt_for_recipient, decrypt_from_sender

__all__ = [
    "KyberKEM",
    "KyberKeypair",
    "DilithiumSig",
    "DilithiumKeypair",
    "encrypt_for_recipient",
    "decrypt_from_sender",
]
