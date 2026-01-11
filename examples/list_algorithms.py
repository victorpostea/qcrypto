"""
List Available Algorithms

Prints all KEM and signature algorithms available in your liboqs build.
"""

import oqs


def main():
    print("=" * 60)
    print("Available KEM Algorithms")
    print("=" * 60)
    for alg in sorted(oqs.get_enabled_KEM_mechanisms()):
        print(f"  {alg}")

    print()
    print("=" * 60)
    print("Available Signature Algorithms")
    print("=" * 60)
    for alg in sorted(oqs.get_enabled_sig_mechanisms()):
        print(f"  {alg}")

    print()
    print(f"Total: {len(oqs.get_enabled_KEM_mechanisms())} KEMs, "
          f"{len(oqs.get_enabled_sig_mechanisms())} signatures")


if __name__ == "__main__":
    main()
