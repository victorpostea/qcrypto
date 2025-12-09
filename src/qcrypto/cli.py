import argparse
import sys
from pathlib import Path

from . import (
    KyberKEM,
    encrypt,
    decrypt,
    encrypt_file,
    decrypt_file,
)


def cmd_gen_key(args):
    alg = args.alg.lower()
    if alg not in ("kyber768",):
        print(f"Unsupported algorithm: {alg}")
        sys.exit(1)

    kem = KyberKEM("Kyber768")
    keys = kem.generate_keypair()

    pub_path = Path(args.public)
    priv_path = Path(args.private)

    kem.save_public_key(pub_path)
    kem.save_private_key(priv_path)

    print(f"Generated Kyber768 keypair:")
    print(f"  Public key:  {pub_path}")
    print(f"  Private key: {priv_path}")


def cmd_encrypt(args):
    pub = Path(args.pub).read_bytes()
    input_path = Path(args.input)
    output_path = Path(args.output)

    encrypt_file(
        public_key=pub,
        input_path=str(input_path),
        output_path=str(output_path),
    )

    print(f"Encrypted → {output_path}")


def cmd_decrypt(args):
    priv = Path(args.key).read_bytes()
    input_path = Path(args.input)
    output_path = Path(args.output)

    decrypt_file(
        private_key=priv,
        input_path=str(input_path),
        output_path=str(output_path),
    )

    print(f"Decrypted → {output_path}")


def main():
    parser = argparse.ArgumentParser(
        prog="qcrypto",
        description="Quantum-safe encryption command line tool",
    )

    sub = parser.add_subparsers(dest="command")

    # gen-key
    gen = sub.add_parser("gen-key", help="Generate a Kyber keypair")
    gen.add_argument("--alg", default="kyber768")
    gen.add_argument("--public", default="public.key")
    gen.add_argument("--private", default="private.key")
    gen.set_defaults(func=cmd_gen_key)

    # encrypt
    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("--pub", required=True)
    enc.add_argument("--in", dest="input", required=True)
    enc.add_argument("--out", dest="output", required=True)
    enc.set_defaults(func=cmd_encrypt)

    # decrypt
    dec = sub.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("--key", required=True)
    dec.add_argument("--in", dest="input", required=True)
    dec.add_argument("--out", dest="output", required=True)
    dec.set_defaults(func=cmd_decrypt)

    # Parse + dispatch
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
