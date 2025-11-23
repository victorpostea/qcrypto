from qcrypto import ClassicMcElieceKEM

def main():
    kem = ClassicMcElieceKEM("Classic-McEliece-348864")
    keys = kem.generate_keypair()

    ct, ss1 = kem.encapsulate(keys.public_key)
    ss2 = kem.decapsulate(ct, private_key=keys.private_key)

    print("Classic McEliece shared secret match:", ss1 == ss2)


if __name__ == "__main__":
    main()
