from dataclasses import dataclass
from typing import Tuple
import oqs
import ctypes as ct


@dataclass
class KyberKeypair:
    public_key: bytes
    secret_key: bytes


class KyberKEM:
    def __init__(self, alg: str = "Kyber768"):
        self.alg = alg
        self._secret_key = None

    def generate_keypair(self) -> KyberKeypair:
        with oqs.KeyEncapsulation(self.alg) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
            self._secret_key = secret_key
            return KyberKeypair(public_key, secret_key)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(self.alg) as kem:
            ct, ss = kem.encap_secret(public_key)
            return ct, ss

    def decapsulate(self, ciphertext: bytes) -> bytes:
        if self._secret_key is None:
            raise ValueError("No secret key stored. Call generate_keypair() first.")

        with oqs.KeyEncapsulation(self.alg) as kem:
            # Init internal buffers (required)
            kem.generate_keypair()

            # Allocate the correct buffer for the SK
            sk_len = kem._kem.contents.length_secret_key
            sk_buf = (ct.c_ubyte * sk_len)(*self._secret_key)

            # *** Critical: set correct attribute ***
            kem.secret_key = sk_buf

            # Now decapsulate normally
            shared_secret = kem.decap_secret(ciphertext)
            return shared_secret

