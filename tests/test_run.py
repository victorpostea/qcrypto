from qcrypto import DilithiumSig, KyberKEM, encrypt_for_recipient, decrypt_from_sender

def test_dilithium():
    sig = DilithiumSig("Dilithium3")
    keys = sig.generate_keypair()

    msg = b"test message"
    signature = sig.sign(keys.secret_key, msg)
    assert sig.verify(keys.public_key, msg, signature)

def test_kyber():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    ct, ss1 = kem.encapsulate(keys.public_key)
    ss2 = kem.decapsulate(ct)
    assert ss1 == ss2

def test_hybrid():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    plaintext = b"super secure pqc message"
    kem_ct, aes_blob = encrypt_for_recipient(keys.public_key, plaintext)
    out = decrypt_from_sender(keys, kem_ct, aes_blob)

    assert out == plaintext
