from __future__ import annotations

import argparse
from collections.abc import Sequence

BLACKLIST = [
    b'BEGIN RSA PRIVATE KEY',
    b'BEGIN DSA PRIVATE KEY',
    b'BEGIN EC PRIVATE KEY',
    b'BEGIN OPENSSH PRIVATE KEY',
    b'BEGIN PRIVATE KEY',
    b'PuTTY-User-Key-File-2',
    b'BEGIN SSH2 ENCRYPTED PRIVATE KEY',
    b'BEGIN PGP PRIVATE KEY BLOCK',
    b'BEGIN ENCRYPTED PRIVATE KEY',
    b'BEGIN OpenVPN Static key V1',
]


def main(argv: Sequence[str] | None = None) -> int:
    return

if __name__ == '__main__':
    raise SystemExit(main())
