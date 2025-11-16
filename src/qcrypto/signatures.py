from dataclasses import dataclass
import oqs
import ctypes as ct


@dataclass
class DilithiumKeypair:
    public_key: bytes
    secret_key: bytes


class DilithiumSig:
    def __init__(self, alg: str = "Dilithium3"):
        self.alg = alg

    def generate_keypair(self) -> DilithiumKeypair:
        with oqs.Signature(self.alg) as sig:
            public_key = sig.generate_keypair()
            secret_key = sig.export_secret_key()
            return DilithiumKeypair(public_key, secret_key)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        with oqs.Signature(self.alg) as signer:
            # Properly load the secret key
            sk_buf = (ct.c_ubyte * signer._sig.contents.length_secret_key)(*secret_key)
            signer.secret_key = sk_buf
            signature = signer.sign(message)
            return signature

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        with oqs.Signature(self.alg) as verifier:
            return verifier.verify(message, signature, public_key)
