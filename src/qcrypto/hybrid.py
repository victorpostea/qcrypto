import os
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .kem import KyberKEM, KyberKeypair


# Ciphertext format:
# [1 byte]  version
# [1 byte]  algorithm id (1 = Kyber768 here)
# [2 bytes] length of Kyber ciphertext (big endian)
# [N bytes] Kyber ciphertext
# [12 bytes] AES-GCM nonce
# [M bytes] AES-GCM ciphertext + tag

VERSION = 1
ALGO_ID_KYBER768 = 1 # extend later for other algorithms


def _derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derive a 256 bit AES key from the Kyber shared secret using HKDF-SHA256.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"qcrypto-hybrid-v1",
    )
    return hkdf.derive(shared_secret)


# High level API: single packaged ciphertext

def encrypt(public_key: bytes, plaintext: bytes) -> bytes:
    """
    Hybrid PQC encrypt.
    Returns a single byte string containing:
    version | algo_id | kyber_ct_len | kyber_ct | nonce | aes_ct+tag
    """
    kem = KyberKEM("Kyber768")
    kem_ct, shared_secret = kem.encapsulate(public_key)

    key = _derive_aes_key(shared_secret)
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)
    aes_ct = aesgcm.encrypt(nonce, plaintext, None)

    kem_ct_len = len(kem_ct)

    header = (
        VERSION.to_bytes(1, "big")
        + ALGO_ID_KYBER768.to_bytes(1, "big")
        + kem_ct_len.to_bytes(2, "big")
    )

    return header + kem_ct + nonce + aes_ct


def decrypt(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts a ciphertext produced by encrypt().
    Expects the same packaged format:
    version | algo_id | kyber_ct_len | kyber_ct | nonce | aes_ct+tag
    """
    if len(ciphertext) < 4:
        raise ValueError("Ciphertext too short to contain header")

    version = ciphertext[0]
    algo_id = ciphertext[1]
    kem_ct_len = int.from_bytes(ciphertext[2:4], "big")

    if version != VERSION:
        raise ValueError(f"Unsupported ciphertext version: {version}")
    if algo_id != ALGO_ID_KYBER768:
        raise ValueError(f"Unsupported algorithm id: {algo_id}")

    offset = 4
    end_kem_ct = offset + kem_ct_len
    if end_kem_ct + 12 + 16 > len(ciphertext):
        # 12 bytes nonce + at least 16 byte tag (AES-GCM)
        raise ValueError("Ciphertext truncated or malformed")

    kem_ct = ciphertext[offset:end_kem_ct]
    offset = end_kem_ct

    nonce = ciphertext[offset:offset + 12]
    aes_ct = ciphertext[offset + 12:]

    kem = KyberKEM("Kyber768")
    shared_secret = kem.decapsulate(kem_ct, private_key=private_key)

    key = _derive_aes_key(shared_secret)
    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, aes_ct, None)


# Backwards compatible low-level API (v0.1.x)

def encrypt_for_recipient(
    recipient_public_key: bytes,
    plaintext: bytes,
) -> Tuple[bytes, bytes]:
    """
    Legacy helper.
    Returns (kem_ciphertext, aes_blob)
    where aes_blob = nonce | ciphertext+tag.
    """
    kem = KyberKEM("Kyber768")
    kem_ciphertext, shared_secret = kem.encapsulate(recipient_public_key)

    key = _derive_aes_key(shared_secret)
    aesgcm = AESGCM(key)

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    blob = nonce + ciphertext
    return kem_ciphertext, blob


def decrypt_from_sender(
    recipient_keys: KyberKeypair,
    kem_ciphertext: bytes,
    aes_blob: bytes,
) -> bytes:
    """
    Legacy helper matching encrypt_for_recipient.
    Uses the recipient's private key to decapsulate, then AES-GCM decrypts.
    """
    kem = KyberKEM("Kyber768")
    shared_secret = kem.decapsulate(
        kem_ciphertext,
        private_key=recipient_keys.private_key,
    )

    key = _derive_aes_key(shared_secret)
    aesgcm = AESGCM(key)

    nonce = aes_blob[:12]
    ciphertext = aes_blob[12:]

    return aesgcm.decrypt(nonce, ciphertext, None)
