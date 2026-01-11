import binascii
import pytest

from qcrypto import (
    DilithiumSig,
    KyberKEM,
    encrypt_for_recipient,
    decrypt_from_sender,
    FalconSig,
    SphincsSig,
    SignatureScheme,
    ClassicMcElieceKEM,
    encrypt,
    decrypt,
    encrypt_file,
    decrypt_file,
    key_fingerprint,
    encrypt_message_armored,
    decrypt_message_armored,
    save_signature_public_key,
    load_signature_public_key,
    save_signature_private_key,
    load_signature_private_key,
    save_signature,
    load_signature,
)

# Expected wire-format constants (per your hybrid.py header)
EXPECTED_VERSION_V2 = 2
EXPECTED_ALGO_ID_KYBER768 = 1


def _parse_v2_header(ct: bytes):
    """
    v2 header layout:
      [0]    version (1 byte)
      [1]    algo_id (1 byte)
      [2:4]  kem_ct_len (2 bytes, big endian)
      [4:8]  header_crc32 (4 bytes, big endian) over ct[0:4]
      [8:...] kem_ct (kem_ct_len bytes)
      then nonce (12 bytes) then aes-gcm ciphertext+tag
    """
    if len(ct) < 8:
        raise ValueError("Ciphertext truncated: incomplete v2 header")

    version = ct[0]
    algo_id = ct[1]
    kem_len = int.from_bytes(ct[2:4], "big")
    crc_stored = int.from_bytes(ct[4:8], "big")

    crc_calc = binascii.crc32(ct[0:4]) & 0xFFFFFFFF

    return version, algo_id, kem_len, crc_stored, crc_calc


def test_dilithium_sign_verify():
    sig = DilithiumSig("Dilithium3")
    keys = sig.generate_keypair()

    msg = b"test message"
    signature = sig.sign(keys.secret_key, msg)
    assert sig.verify(keys.public_key, msg, signature)


def test_falcon_sign_verify():
    sig = FalconSig("Falcon-512")
    keys = sig.generate_keypair()

    msg = b"falcon test message"
    signature = sig.sign(keys.secret_key, msg)
    assert sig.verify(keys.public_key, msg, signature)


def test_sphincs_sign_verify():
    sig = SphincsSig("SPHINCS+-SHA2-128f-simple")
    keys = sig.generate_keypair()

    msg = b"sphincs test"
    signature = sig.sign(keys.secret_key, msg)
    assert sig.verify(keys.public_key, msg, signature)


def test_signature_scheme_generic_falcon():
    scheme = SignatureScheme("Falcon-512")
    keys = scheme.generate_keypair()

    msg = b"generic falcon"
    sig_bytes = scheme.sign(keys.secret_key, msg)
    assert scheme.verify(keys.public_key, msg, sig_bytes)


def test_signature_scheme_generic_sphincs():
    scheme = SignatureScheme("SPHINCS+-SHA2-128f-simple")
    keys = scheme.generate_keypair()

    msg = b"generic sphincs"
    sig_bytes = scheme.sign(keys.secret_key, msg)
    assert scheme.verify(keys.public_key, msg, sig_bytes)


def test_kyber_round_trip_shared_secret():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    ct, ss1 = kem.encapsulate(keys.public_key)
    ss2 = kem.decapsulate(ct, private_key=keys.private_key)
    assert ss1 == ss2


def test_classic_mceliece_round_trip():
    kem = ClassicMcElieceKEM()  # default param set
    keys = kem.generate_keypair()

    ct, ss1 = kem.encapsulate(keys.public_key)
    ss2 = kem.decapsulate(ct, private_key=keys.private_key)
    assert ss1 == ss2


def test_hybrid_legacy_encrypt_for_recipient_round_trip():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    plaintext = b"super secure pqc message"
    kem_ct, aes_blob = encrypt_for_recipient(keys.public_key, plaintext)
    out = decrypt_from_sender(keys, kem_ct, aes_blob)

    assert out == plaintext


def test_new_encrypt_decrypt_round_trip():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    msg = b"hello post quantum world"
    ct = encrypt(keys.public_key, msg)
    out = decrypt(keys.private_key, ct)
    assert out == msg


def test_ciphertext_header_v2_fields_and_checksum():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    ct = encrypt(keys.public_key, b"x")

    version, algo_id, kem_len, crc_stored, crc_calc = _parse_v2_header(ct)

    assert version == EXPECTED_VERSION_V2
    assert algo_id == EXPECTED_ALGO_ID_KYBER768
    assert kem_len > 0
    assert crc_stored == crc_calc

    # Ensure kem_ct actually exists inside ciphertext
    assert len(ct) >= 8 + kem_len + 12 + 16  # header + kem + nonce + tag(min)


def test_reject_wrong_version():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    ct = bytearray(encrypt(keys.public_key, b"msg"))
    ct[0] = 99  # corrupt version byte

    with pytest.raises(ValueError):
        decrypt(keys.private_key, bytes(ct))


def test_reject_wrong_algo_id():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    ct = bytearray(encrypt(keys.public_key, b"msg"))
    ct[1] = 4  # unknown algo id

    with pytest.raises(ValueError):
        decrypt(keys.private_key, bytes(ct))


def test_reject_corrupted_header_checksum():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    ct = bytearray(encrypt(keys.public_key, b"msg"))

    # Flip one bit inside the header prefix that is checksummed (bytes 0..3)
    ct[2] ^= 0x01

    with pytest.raises(ValueError):
        decrypt(keys.private_key, bytes(ct))


def test_reject_truncated_ciphertext():
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    full = encrypt(keys.public_key, b"msg")

    # Truncate to less than v2 header
    truncated = full[:6]
    with pytest.raises(ValueError):
        decrypt(keys.private_key, truncated)

    # Truncate after header but before full payload
    truncated2 = full[:-10]
    with pytest.raises(ValueError):
        decrypt(keys.private_key, truncated2)


def test_key_serialization_round_trip_raw(tmp_path):
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    pub_path = tmp_path / "pub.key"
    priv_path = tmp_path / "priv.key"

    # Save (raw)
    kem.save_public_key(str(pub_path), encoding="raw")
    kem.save_private_key(str(priv_path), encoding="raw")

    # Load
    pub2 = KyberKEM.load_public_key(str(pub_path), encoding="raw")
    priv2 = KyberKEM.load_private_key(str(priv_path), encoding="raw")

    msg = b"testing serialization"
    ct = encrypt(pub2, msg)
    out = decrypt(priv2, ct)
    assert out == msg


def test_key_serialization_round_trip_armor(tmp_path):
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    pub_path = tmp_path / "pub.asc"
    priv_path = tmp_path / "priv.asc"

    # Save armored
    kem.save_public_key(str(pub_path), encoding="armor")
    kem.save_private_key(str(priv_path), encoding="armor")

    # Load (loader should auto-detect armor too, but keep explicit)
    pub2 = KyberKEM.load_public_key(str(pub_path), encoding="armor")
    priv2 = KyberKEM.load_private_key(str(priv_path), encoding="armor")

    msg = b"armor round trip"
    ct = encrypt(pub2, msg)
    out = decrypt(priv2, ct)
    assert out == msg


def test_private_key_encryption_round_trip_if_supported(tmp_path):
    """
    If your kem.py supports encrypting private keys via passphrase,
    this test verifies it. If not supported, delete this test.
    """
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    priv_path = tmp_path / "priv.enc"

    passphrase = "correct horse battery staple"

    kem.save_private_key(str(priv_path), encoding="raw", passphrase=passphrase)
    priv2 = KyberKEM.load_private_key(str(priv_path), encoding="raw", passphrase=passphrase)

    msg = b"encrypted private key round trip"
    ct = encrypt(keys.public_key, msg)
    out = decrypt(priv2, ct)
    assert out == msg

    # Wrong passphrase should fail
    with pytest.raises(Exception):
        KyberKEM.load_private_key(str(priv_path), encoding="raw", passphrase="wrong")


def test_fingerprint_stable_and_round_trip(tmp_path):
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    fp1 = key_fingerprint(keys.public_key)
    fp2 = key_fingerprint(keys.public_key)
    assert fp1 == fp2
    assert isinstance(fp1, str)
    assert len(fp1) == 32  # 16 bytes -> 32 hex chars

    # Round-trip through armor file and confirm fingerprint is preserved
    pub_path = tmp_path / "pub.asc"
    kem.save_public_key(str(pub_path), encoding="armor")
    pub2 = KyberKEM.load_public_key(str(pub_path), encoding="armor")
    assert key_fingerprint(pub2) == fp1

    # Different key => different fingerprint (overwhelmingly likely)
    keys2 = kem.generate_keypair()
    fp_other = key_fingerprint(keys2.public_key)
    assert fp_other != fp1


def test_file_encrypt_decrypt_round_trip(tmp_path):
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    plaintext = b"This is a test file for PQC hybrid encryption.\n" * 50
    input_file = tmp_path / "input.txt"
    encrypted_file = tmp_path / "encrypted.bin"
    output_file = tmp_path / "output.txt"

    input_file.write_bytes(plaintext)

    encrypt_file(
        public_key=keys.public_key,
        input_path=str(input_file),
        output_path=str(encrypted_file),
    )

    assert encrypted_file.exists()
    assert encrypted_file.stat().st_size > 0

    decrypt_file(
        private_key=keys.private_key,
        input_path=str(encrypted_file),
        output_path=str(output_file),
    )

    assert output_file.exists()
    assert output_file.read_bytes() == plaintext


def test_armored_message_round_trip():
    """Test encrypt_message_armored and decrypt_message_armored."""
    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    plaintext = b"This is a secret message for armored transport."

    armored = encrypt_message_armored(keys.public_key, plaintext)

    # Check it's properly formatted
    assert armored.startswith("-----BEGIN QCRYPTO MESSAGE-----")
    assert armored.strip().endswith("-----END QCRYPTO MESSAGE-----")

    recovered = decrypt_message_armored(keys.private_key, armored)
    assert recovered == plaintext


def test_signature_file_serialization_round_trip(tmp_path):
    """Test save/load for signature keys and signatures."""
    alg = "Dilithium3"
    scheme = SignatureScheme(alg)
    keys = scheme.generate_keypair()

    pub_path = tmp_path / "sig.pub"
    priv_path = tmp_path / "sig.key"
    sig_path = tmp_path / "message.sig"

    # Save keys
    save_signature_public_key(str(pub_path), keys.public_key, alg, armored=True)
    save_signature_private_key(str(priv_path), keys.secret_key, alg, armored=True)

    # Load keys
    loaded_alg, loaded_pk = load_signature_public_key(str(pub_path))
    loaded_alg2, loaded_sk = load_signature_private_key(str(priv_path))

    assert loaded_alg == alg
    assert loaded_alg2 == alg
    assert loaded_pk == keys.public_key
    assert loaded_sk == keys.secret_key

    # Sign with loaded key
    msg = b"Test message for signature serialization"
    sig_bytes = scheme.sign(loaded_sk, msg)

    # Save and load signature
    save_signature(str(sig_path), sig_bytes, alg, armored=True)
    sig_alg, loaded_sig = load_signature(str(sig_path))

    assert sig_alg == alg
    assert loaded_sig == sig_bytes

    # Verify with loaded key and signature
    assert scheme.verify(loaded_pk, msg, loaded_sig)


def test_signature_scheme_parameter_order():
    """
    Regression test: ensure sign(secret_key, message) and
    verify(public_key, message, signature) parameter order is correct.
    """
    scheme = SignatureScheme("Dilithium3")
    keys = scheme.generate_keypair()

    msg = b"parameter order test"

    # sign takes (secret_key, message)
    sig = scheme.sign(keys.secret_key, msg)

    # verify takes (public_key, message, signature)
    assert scheme.verify(keys.public_key, msg, sig)

    # Wrong key should fail
    other_keys = scheme.generate_keypair()
    assert not scheme.verify(other_keys.public_key, msg, sig)
