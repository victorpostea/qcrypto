import oqs

def main():
    print("Enabled KEM algorithms:")
    for alg in oqs.get_enabled_KEM_mechanisms():
        print("  -", alg)

    print("\nEnabled Signature algorithms:")
    for alg in oqs.get_enabled_sig_mechanisms():
        print("  -", alg)

if __name__ == "__main__":
    main()
