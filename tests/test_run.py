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

    kem.save_public_key()
    kem.save_private_key()

    saved_pub_key = kem.load_public_key()

    ct, ss1 = kem.encapsulate(saved_pub_key)
    ss2 = kem.decapsulate(ct)
    assert ss1 == ss2

def test_hybrid():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    plaintext = b"super secure pqc message"
    kem_ct, aes_blob = encrypt_for_recipient(keys.public_key, plaintext)
    out = decrypt_from_sender(keys, kem_ct, aes_blob)

    assert out == plaintext

def test_new_hybrid_encrypt_decrypt():
    from qcrypto import KyberKEM, encrypt, decrypt

    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    msg = b"hello post quantum world"
    ct = encrypt(keys.public_key, msg)

    out = decrypt(keys.private_key, ct)
    assert out == msg

def test_ciphertext_header_fields():
    from qcrypto import KyberKEM, encrypt

    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    ct = encrypt(keys.public_key, b"x")

    version = ct[0]
    algo_id = ct[1]

    assert version == 1
    assert algo_id == 1

def test_key_serialization_round_trip():
    from qcrypto import KyberKEM, encrypt, decrypt

    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    # save keys
    kem.save_public_key("pub.key")
    kem.save_private_key("priv.key")

    # load keys
    pub2 = KyberKEM.load_public_key("pub.key")
    priv2 = KyberKEM.load_private_key("priv.key")

    msg = b"testing serialization"
    ct = encrypt(pub2, msg)
    out = decrypt(priv2, ct)

    assert out == msg

def test_reject_wrong_version():
    from qcrypto import KyberKEM, encrypt, decrypt

    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    ct = bytearray(encrypt(keys.public_key, b"msg"))
    ct[0] = 99   # corrupt version byte

    try:
        decrypt(keys.private_key, bytes(ct))
        assert False, "Expected ValueError for wrong version"
    except ValueError:
        pass


def test_reject_wrong_algo_id():
    from qcrypto import KyberKEM, encrypt, decrypt

    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    ct = bytearray(encrypt(keys.public_key, b"msg"))
    ct[1] = 4  # unknown algo

    try:
        decrypt(keys.private_key, bytes(ct))
        assert False, "Expected ValueError for wrong algo id"
    except ValueError:
        pass

