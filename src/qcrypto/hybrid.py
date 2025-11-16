import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .kem import KyberKEM, KyberKeypair
import os


def _derive_aes_key(shared_secret: bytes) -> bytes:
    # Hash down to 256-bit AES key
    return hashlib.sha256(shared_secret).digest()


def encrypt_for_recipient(
    recipient_public_key: bytes,
    plaintext: bytes,
) -> Tuple[bytes, bytes]:
    """
    Returns (kem_ciphertext, aes_blob)
    where aes_blob = nonce | ciphertext+tag
    """
    kem = KyberKEM()
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
    Decrypts the message encrypted by encrypt_for_recipient.
    Uses the recipient's stored Kyber secret key.
    """
    kem = KyberKEM()
    kem._secret_key = recipient_keys.secret_key   # load SK manually

    shared_secret = kem.decapsulate(kem_ciphertext)

    key = _derive_aes_key(shared_secret)
    aesgcm = AESGCM(key)

    nonce = aes_blob[:12]
    ciphertext = aes_blob[12:]

    return aesgcm.decrypt(nonce, ciphertext, None)
