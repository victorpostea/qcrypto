import qcrypto

# Generate or load keys as you already do
kem = qcrypto.KyberKEM("Kyber768")
kp = kem.generate_keypair()

# Encrypt a file
qcrypto.encrypt_file(
    public_key=kp.public_key,
    input_path="plaintext.pdf",
    output_path="plaintext.pdf.qc",
)

# Decrypt it back
qcrypto.decrypt_file(
    private_key=kp.private_key,
    input_path="plaintext.pdf.qc",
    output_path="plaintext.dec.pdf",
)
