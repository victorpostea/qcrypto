import argparse
import sys
from pathlib import Path
from getpass import getpass
from typing import Optional

from . import (
    KyberKEM,
    encrypt_file,
    decrypt_file,
)

# Default key locations
DEFAULT_DIR = Path.home() / ".qcrypto"
DEFAULT_PRIV = DEFAULT_DIR / "private.key"
DEFAULT_PUB = DEFAULT_DIR / "public.key"


def _ensure_default_dir() -> None:
    # 0700 so only the user can read/write/execute the directory
    DEFAULT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)


def _resolve_public_key_path(arg_value: Optional[str] = None) -> Path:
    return Path(arg_value) if arg_value else DEFAULT_PUB


def _resolve_private_key_path(arg_value: Optional[str] = None) -> Path:
    return Path(arg_value) if arg_value else DEFAULT_PRIV


def cmd_gen_key(args):
    alg = args.alg.lower()
    if alg not in ("kyber768",):
        print(f"Unsupported algorithm: {alg}")
        sys.exit(1)

    kem = KyberKEM("Kyber768")
    kem.generate_keypair()

    # Default to ~/.qcrypto/{public,private}.key unless overridden
    pub_path = _resolve_public_key_path(args.public)
    priv_path = _resolve_private_key_path(args.private)

    # If user is using defaults, ensure ~/.qcrypto exists
    if args.public is None or args.private is None:
        _ensure_default_dir()

    # Safety: avoid accidental overwrite unless --force
    if not args.force:
        if pub_path.exists() or priv_path.exists():
            print("Refusing to overwrite existing key(s).")
            print(f"  Public key:  {pub_path} {'(exists)' if pub_path.exists() else ''}")
            print(f"  Private key: {priv_path} {'(exists)' if priv_path.exists() else ''}")
            print("Use --force to overwrite, or specify different --public/--private paths.")
            sys.exit(1)

    # Ask for passphrase if flag provided without one
    passphrase = args.password
    if args.password is True:  # user passed --pass with no value
        passphrase = getpass("Enter passphrase for private key: ")

    kem.save_public_key(pub_path)
    kem.save_private_key(priv_path, passphrase=passphrase)

    print("Generated Kyber768 keypair:")
    print(f"  Public key:  {pub_path}")
    print(f"  Private key: {priv_path}")
    if passphrase:
        print("  (private key encrypted with passphrase)")


def cmd_encrypt(args):
    pub_path = _resolve_public_key_path(args.pub)

    if args.pub is None:
        # using default path; ensure directory exists (but do not auto-generate keys here)
        _ensure_default_dir()

    if not pub_path.exists():
        print(f"Public key not found: {pub_path}")
        print("Run: qcrypto gen-key")
        sys.exit(1)

    pub = pub_path.read_bytes()
    input_path = Path(args.input)
    output_path = Path(args.output)

    encrypt_file(
        public_key=pub,
        input_path=str(input_path),
        output_path=str(output_path),
    )

    print(f"Encrypted → {output_path}")


def cmd_decrypt(args):
    priv_path = _resolve_private_key_path(args.key)

    if args.key is None:
        _ensure_default_dir()

    if not priv_path.exists():
        print(f"Private key not found: {priv_path}")
        print("Run: qcrypto gen-key")
        sys.exit(1)

    # Handle passphrase input
    passphrase = args.password
    if args.password is True:
        passphrase = getpass("Passphrase: ")

    # Load private key using KEM loader
    priv = KyberKEM.load_private_key(str(priv_path), passphrase=passphrase)

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
    # If omitted, defaults to ~/.qcrypto/public.key and ~/.qcrypto/private.key
    gen.add_argument("--public", default=None)
    gen.add_argument("--private", default=None)
    gen.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing key files if they already exist",
    )
    gen.add_argument(
        "--pass",
        dest="password",
        nargs="?",
        const=True,  # --pass with no value triggers prompt
        help="Encrypt private key with a passphrase",
    )
    gen.set_defaults(func=cmd_gen_key)

    # encrypt
    enc = sub.add_parser("encrypt", help="Encrypt a file")
    # If omitted, defaults to ~/.qcrypto/public.key
    enc.add_argument("--pub", default=None)
    enc.add_argument("--in", dest="input", required=True)
    enc.add_argument("--out", dest="output", required=True)
    enc.set_defaults(func=cmd_encrypt)

    # decrypt
    dec = sub.add_parser("decrypt", help="Decrypt a file")
    # If omitted, defaults to ~/.qcrypto/private.key
    dec.add_argument("--key", default=None)
    dec.add_argument("--in", dest="input", required=True)
    dec.add_argument("--out", dest="output", required=True)
    dec.add_argument(
        "--pass",
        dest="password",
        nargs="?",
        const=True,
        help="Passphrase for encrypted private key",
    )
    dec.set_defaults(func=cmd_decrypt)

    # Parse + dispatch
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
