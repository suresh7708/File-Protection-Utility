#!/usr/bin/env python3
"""
File Protection Utility
=======================
Converts a file into a password-protected format and restores it on demand.

Uses only the Python standard library.

Security design (encrypt-then-MAC):
  * Key derivation : PBKDF2-HMAC-SHA256 (random salt, 600,000 iterations)
                     -> 64 bytes split into an encryption key and a MAC key
  * Encryption     : keystream from HMAC-SHA256(enc_key, nonce || counter)
                     XORed with the data (a PRF-based stream cipher)
  * Integrity      : HMAC-SHA256 over header + ciphertext, verified BEFORE
                     any decryption happens (wrong password or a tampered
                     file is detected and rejected)

Protected file layout:
  MAGIC(4) | ITERATIONS(4) | SALT(16) | NONCE(16) | CIPHERTEXT | TAG(32)

NOTE: This is an educational project. For production systems use a vetted
library (e.g. `cryptography` with AES-GCM or Fernet).

Usage:
  python file_protector.py protect  secret.txt              -> secret.txt.fpu
  python file_protector.py restore  secret.txt.fpu          -> secret.txt
  python file_protector.py protect  a.pdf -o locked.bin
  python file_protector.py restore  locked.bin -o a.pdf
  python file_protector.py protect  a.pdf --delete-original
"""

import argparse
import getpass
import hashlib
import hmac
import os
import struct
import sys

MAGIC = b"FPU1"
SALT_LEN = 16
NONCE_LEN = 16
TAG_LEN = 32
ITERATIONS = 600_000
CHUNK = 64 * 1024  # 64 KB; must be a multiple of 32 (SHA-256 block output)
EXT = ".fpu"
HEADER_LEN = len(MAGIC) + 4 + SALT_LEN + NONCE_LEN


class ProtectionError(Exception):
    """Raised for any user-facing failure (bad password, bad file, etc.)."""


# --------------------------------------------------------------------------
# Crypto helpers
# --------------------------------------------------------------------------
def derive_keys(password: str, salt: bytes, iterations: int):
    """Derive independent encryption and MAC keys from the password."""
    material = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=64
    )
    return material[:32], material[32:]


def keystream_xor(data: bytes, enc_key: bytes, nonce: bytes, offset: int) -> bytes:
    """XOR `data` with the keystream starting at byte `offset` (multiple of 32)."""
    out = bytearray(len(data))
    counter = offset // 32
    pos = 0
    while pos < len(data):
        block = hmac.new(
            enc_key, nonce + struct.pack(">Q", counter), hashlib.sha256
        ).digest()
        piece = data[pos:pos + 32]
        for i, b in enumerate(piece):
            out[pos + i] = b ^ block[i]
        pos += 32
        counter += 1
    return bytes(out)


# --------------------------------------------------------------------------
# Protect
# --------------------------------------------------------------------------
def protect_file(src: str, dst: str, password: str) -> None:
    if not os.path.isfile(src):
        raise ProtectionError(f"Source file not found: {src}")
    if os.path.abspath(src) == os.path.abspath(dst):
        raise ProtectionError("Output path must differ from the input path.")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    enc_key, mac_key = derive_keys(password, salt, ITERATIONS)

    header = MAGIC + struct.pack(">I", ITERATIONS) + salt + nonce
    mac = hmac.new(mac_key, header, hashlib.sha256)

    tmp = dst + ".tmp"
    try:
        with open(src, "rb") as fin, open(tmp, "wb") as fout:
            fout.write(header)
            offset = 0
            while True:
                chunk = fin.read(CHUNK)
                if not chunk:
                    break
                ct = keystream_xor(chunk, enc_key, nonce, offset)
                mac.update(ct)
                fout.write(ct)
                offset += len(chunk)
            fout.write(mac.digest())
        os.replace(tmp, dst)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# --------------------------------------------------------------------------
# Restore
# --------------------------------------------------------------------------
def restore_file(src: str, dst: str, password: str) -> None:
    if not os.path.isfile(src):
        raise ProtectionError(f"Protected file not found: {src}")

    size = os.path.getsize(src)
    if size < HEADER_LEN + TAG_LEN:
        raise ProtectionError("File is too small to be a protected file.")

    with open(src, "rb") as fin:
        header = fin.read(HEADER_LEN)
        if header[:4] != MAGIC:
            raise ProtectionError("Not a file produced by this utility.")
        iterations = struct.unpack(">I", header[4:8])[0]
        salt = header[8:8 + SALT_LEN]
        nonce = header[8 + SALT_LEN:]

        enc_key, mac_key = derive_keys(password, salt, iterations)
        ct_len = size - HEADER_LEN - TAG_LEN

        # Pass 1: verify integrity / password BEFORE producing any output.
        mac = hmac.new(mac_key, header, hashlib.sha256)
        remaining = ct_len
        while remaining > 0:
            data = fin.read(min(CHUNK, remaining))
            mac.update(data)
            remaining -= len(data)
        tag = fin.read(TAG_LEN)
        if not hmac.compare_digest(mac.digest(), tag):
            raise ProtectionError(
                "Wrong password, or the file has been corrupted/tampered with."
            )

        # Pass 2: decrypt.
        fin.seek(HEADER_LEN)
        tmp = dst + ".tmp"
        try:
            with open(tmp, "wb") as fout:
                offset = 0
                remaining = ct_len
                while remaining > 0:
                    data = fin.read(min(CHUNK, remaining))
                    fout.write(keystream_xor(data, enc_key, nonce, offset))
                    offset += len(data)
                    remaining -= len(data)
            os.replace(tmp, dst)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def get_password(confirm: bool) -> str:
    pw = getpass.getpass("Password: ")
    if not pw:
        raise ProtectionError("Password cannot be empty.")
    if confirm and getpass.getpass("Confirm password: ") != pw:
        raise ProtectionError("Passwords do not match.")
    return pw


def default_restore_name(path: str) -> str:
    if path.endswith(EXT):
        return path[: -len(EXT)]
    return path + ".restored"


def confirm_overwrite(path: str) -> None:
    if os.path.exists(path):
        ans = input(f"'{path}' already exists. Overwrite? [y/N]: ").strip().lower()
        if ans != "y":
            raise ProtectionError("Cancelled; nothing was overwritten.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Protect a file with a password, and restore it later."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("protect", help="convert a file to protected format")
    p.add_argument("file")
    p.add_argument("-o", "--output", help="output path (default: <file>.fpu)")
    p.add_argument("--delete-original", action="store_true",
                   help="remove the original file after protecting it")

    r = sub.add_parser("restore", help="restore a protected file")
    r.add_argument("file")
    r.add_argument("-o", "--output", help="output path (default: strips .fpu)")

    args = parser.parse_args()

    try:
        if args.command == "protect":
            out = args.output or args.file + EXT
            confirm_overwrite(out)
            pw = get_password(confirm=True)
            protect_file(args.file, out, pw)
            print(f"Protected -> {out}")
            if args.delete_original:
                os.remove(args.file)
                print(f"Deleted original: {args.file}")
        else:
            out = args.output or default_restore_name(args.file)
            confirm_overwrite(out)
            pw = get_password(confirm=False)
            restore_file(args.file, out, pw)
            print(f"Restored -> {out}")
    except ProtectionError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
