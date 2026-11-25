#!/usr/bin/env python3
"""Seal and open the client payload used by the static unlock page.

The vault is encrypted with a key derived from the repository passphrase.
The browser derives the same key, wraps it to the waiting runner with RSA-OAEP,
and the runner uses it to open the vault.  The relay only ever sees ciphertext.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path
from typing import Any

ITERATIONS = 600_000
META_FORMAT = "secure-session"
VAULT_FORMAT = "secure-session-vault"
COMMAND_FORMAT = "secure-session-command"
FILES_FORMAT = "secure-session-files"
VAULT_DOMAIN = b"secure-session-vault-v1\x00"
COMMAND_DOMAIN = b"secure-session-command-v1\x00"
PASSWORD_ENV = "SESSION_PASSPHRASE"
MAX_FILE = 2 * 1024 * 1024


class VaultError(Exception):
    """Invalid password, payload, or crypto operation."""


def b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def b64d(value: Any, label: str = "value") -> bytes:
    if not isinstance(value, str):
        raise VaultError(f"invalid {label}")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as exc:
        raise VaultError(f"invalid {label}") from exc


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64ud(value: str) -> bytes:
    if not isinstance(value, str):
        raise VaultError("invalid key")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except Exception:
        try:
            return base64.b64decode(padded, validate=True)
        except Exception as exc:
            raise VaultError("invalid key") from exc


def read_password(password_env: str | None) -> str:
    value = os.environ.get(password_env or PASSWORD_ENV, "")
    if not value:
        if not sys.stdin.isatty():
            raise VaultError(f"repository secret {password_env or PASSWORD_ENV} is not configured")
        value = getpass.getpass("Passphrase: ")
    value = value.rstrip("\r\n")
    if len(value) < 16:
        raise VaultError("passphrase must be at least 16 characters")
    return value


def derive_key(password: str, salt: bytes, iterations: int = ITERATIONS) -> bytes:
    if len(password) < 16:
        raise VaultError("passphrase must be at least 16 characters")
    if iterations < 100_000:
        raise VaultError("invalid KDF iteration count")
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=64
    )


def split_key(key: bytes) -> tuple[bytes, bytes]:
    if not isinstance(key, bytes) or len(key) != 64:
        raise VaultError("invalid session key")
    return key[:32], key[32:]


def openssl_aes(data: bytes, key: bytes, iv: bytes, *, decrypt: bool) -> bytes:
    command = ["openssl", "enc", "-aes-256-cbc", "-nosalt", "-K", key.hex(), "-iv", iv.hex()]
    if decrypt:
        command.append("-d")
    try:
        result = subprocess.run(
            command,
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as exc:
        raise VaultError("OpenSSL is required") from exc
    if result.returncode:
        raise VaultError("decryption failed")
    return result.stdout


def seal_bytes(
    key: bytes,
    plaintext: bytes,
    domain: bytes,
    *,
    fmt: str,
) -> dict[str, Any]:
    if not plaintext:
        raise VaultError("cannot seal an empty payload")
    aes_key, mac_key = split_key(key)
    iv = secrets.token_bytes(16)
    ciphertext = openssl_aes(plaintext, aes_key, iv, decrypt=False)
    tag = hmac.new(mac_key, domain + iv + ciphertext, hashlib.sha256).digest()
    return {
        "format": fmt,
        "version": 1,
        "iv": b64e(iv),
        "ciphertext": b64e(ciphertext),
        "tag": b64e(tag),
    }


def open_bytes(
    key: bytes,
    payload: Any,
    domain: bytes,
    *,
    fmt: str,
) -> bytes:
    if not isinstance(payload, dict):
        raise VaultError("invalid sealed payload")
    if payload.get("format") != fmt or payload.get("version") != 1:
        raise VaultError("unsupported sealed payload")
    iv = b64d(payload.get("iv"), "IV")
    ciphertext = b64d(payload.get("ciphertext"), "ciphertext")
    tag = b64d(payload.get("tag"), "authentication tag")
    if len(iv) != 16 or not ciphertext or len(ciphertext) % 16 or len(tag) != 32:
        raise VaultError("malformed sealed payload")
    aes_key, mac_key = split_key(key)
    expected = hmac.new(mac_key, domain + iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise VaultError("incorrect passphrase or modified payload")
    return openssl_aes(ciphertext, aes_key, iv, decrypt=True)


def default_meta() -> dict[str, Any]:
    return {
        "format": META_FORMAT,
        "version": 1,
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": ITERATIONS,
        "salt": b64e(secrets.token_bytes(16)),
    }


def validate_meta(meta: Any) -> dict[str, Any]:
    if not isinstance(meta, dict):
        raise VaultError("invalid metadata")
    expected = {
        "format": META_FORMAT,
        "version": 1,
        "kdf": "PBKDF2-HMAC-SHA256",
    }
    if any(meta.get(key) != value for key, value in expected.items()):
        raise VaultError("unsupported metadata format")
    iterations = meta.get("iterations")
    if not isinstance(iterations, int) or not 100_000 <= iterations <= 10_000_000:
        raise VaultError("invalid KDF iteration count")
    salt = b64d(meta.get("salt"), "salt")
    if len(salt) != 16:
        raise VaultError("invalid salt")
    return {
        "format": META_FORMAT,
        "version": 1,
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": iterations,
        "salt": b64e(salt),
    }


def load_meta(path: Path | None) -> dict[str, Any]:
    if path is not None and path.is_file():
        try:
            return validate_meta(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError, VaultError):
            pass
    return default_meta()


def seal_vault(
    files: dict[str, bytes],
    password: str,
    *,
    meta: dict[str, Any] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    if not files:
        raise VaultError("no files to seal")
    meta = validate_meta(meta or default_meta())
    key = derive_key(password, b64d(meta["salt"]), meta["iterations"])
    manifest = {
        "format": FILES_FORMAT,
        "version": 1,
        "files": {
            name: {"mode": 0o700, "data": b64e(data)}
            for name, data in files.items()
        },
    }
    sealed = seal_bytes(
        key,
        json.dumps(manifest, separators=(",", ":")).encode("utf-8"),
        VAULT_DOMAIN,
        fmt=VAULT_FORMAT,
    )
    vault = {
        "format": VAULT_FORMAT,
        "version": 1,
        "meta": meta,
        **{key: sealed[key] for key in ("iv", "ciphertext", "tag")},
    }
    return json.dumps(vault, separators=(",", ":")).encode("utf-8") + b"\n", meta


def open_vault(
    vault_path: Path,
    *,
    key: bytes | None = None,
    password: str | None = None,
) -> tuple[dict[str, tuple[bytes, int]], dict[str, Any]]:
    try:
        vault = json.loads(vault_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VaultError("could not read the vault") from exc
    if not isinstance(vault, dict):
        raise VaultError("invalid vault")
    if vault.get("format") != VAULT_FORMAT or vault.get("version") != 1:
        raise VaultError("unsupported vault format")
    meta = validate_meta(vault.get("meta"))
    if key is None:
        if password is None:
            raise VaultError("a key or passphrase is required")
        key = derive_key(password, b64d(meta["salt"]), meta["iterations"])
    clear = open_bytes(
        key,
        {
            "format": VAULT_FORMAT,
            "version": 1,
            "iv": vault.get("iv"),
            "ciphertext": vault.get("ciphertext"),
            "tag": vault.get("tag"),
        },
        VAULT_DOMAIN,
        fmt=VAULT_FORMAT,
    )
    try:
        manifest = json.loads(clear.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaultError("invalid vault contents") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("format") != FILES_FORMAT
        or manifest.get("version") != 1
        or not isinstance(manifest.get("files"), dict)
        or not manifest["files"]
    ):
        raise VaultError("invalid vault manifest")
    files: dict[str, tuple[bytes, int]] = {}
    for name, entry in manifest["files"].items():
        if (
            not isinstance(name, str)
            or not name
            or name in (".", "..")
            or "/" in name
            or "\\" in name
            or not isinstance(entry, dict)
        ):
            raise VaultError("invalid file name in vault")
        data = b64d(entry.get("data"), f"data for {name}")
        if len(data) > MAX_FILE:
            raise VaultError(f"{name} is too large")
        mode = entry.get("mode", 0o600)
        if not isinstance(mode, int) or not 0 <= mode <= 0o777:
            mode = 0o600
        files[name] = (data, mode)
    return files, meta


def write_files(files: dict[str, tuple[bytes, int]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(out_dir, 0o700)
    except OSError:
        pass
    for name, (data, mode) in files.items():
        target = out_dir / name
        target.write_bytes(data)
        try:
            os.chmod(target, mode)
        except OSError:
            pass


def read_file(path: Path) -> bytes:
    if not path.is_file():
        raise VaultError(f"missing file: {path}")
    data = path.read_bytes()
    if len(data) > MAX_FILE:
        raise VaultError(f"file is too large: {path}")
    return data


def command_seal(args: argparse.Namespace) -> int:
    meta_path = Path(args.meta)
    vault_path = Path(args.vault)
    meta = load_meta(meta_path)
    password = read_password(args.password_env)
    files = {Path(item).name: read_file(Path(item)) for item in args.file}
    sealed, meta = seal_vault(files, password, meta=meta)
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    vault_path.write_bytes(sealed)
    try:
        os.chmod(vault_path, 0o600)
    except OSError:
        pass
    print(f"Sealed {len(files)} file(s).")
    return 0


def command_open(args: argparse.Namespace) -> int:
    key = None
    if args.key:
        key = b64ud(args.key)
    elif args.key_file:
        try:
            key = b64ud(Path(args.key_file).read_text(encoding="ascii").strip())
        except OSError as exc:
            raise VaultError("could not read the session key") from exc
    password = None if key is not None else read_password(args.password_env)
    files, meta = open_vault(Path(args.vault), key=key, password=password)
    write_files(files, Path(args.out))
    print(f"Opened {len(files)} file(s).")
    return 0


def command_verify(args: argparse.Namespace) -> int:
    meta_path = Path(args.meta)
    vault_path = Path(args.vault)
    try:
        public_meta = validate_meta(json.loads(meta_path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        raise VaultError("could not read the public metadata") from exc
    files, vault_meta = open_vault(
        vault_path, password=read_password(args.password_env)
    )
    if public_meta != vault_meta:
        raise VaultError("public metadata does not match the vault")
    if "client.sh" not in files or "tunnel.py" not in files:
        raise VaultError("vault is missing required files")
    print(f"Vault verified ({len(files)} file(s)).")
    return 0


def command_init_meta(args: argparse.Namespace) -> int:
    path = Path(args.meta)
    meta = load_meta(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {path}.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)

    init_meta = sub.add_parser("init-meta", help="create or normalize the public metadata")
    init_meta.add_argument("--meta", required=True)
    init_meta.set_defaults(func=command_init_meta)

    seal = sub.add_parser("seal", help="encrypt files into the vault")
    seal.add_argument("--meta", required=True)
    seal.add_argument("--vault", required=True)
    seal.add_argument("--file", action="append", required=True)
    seal.add_argument("--password-env", default=PASSWORD_ENV)
    seal.set_defaults(func=command_seal)

    open_cmd = sub.add_parser("open", help="decrypt the vault into a directory")
    open_cmd.add_argument("--vault", required=True)
    open_cmd.add_argument("--out", required=True)
    open_cmd.add_argument("--key")
    open_cmd.add_argument("--key-file")
    open_cmd.add_argument("--password-env", default=PASSWORD_ENV)
    open_cmd.set_defaults(func=command_open)

    verify = sub.add_parser("verify", help="verify the vault without printing its contents")
    verify.add_argument("--vault", required=True)
    verify.add_argument("--meta", required=True)
    verify.add_argument("--password-env", default=PASSWORD_ENV)
    verify.set_defaults(func=command_verify)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return int(args.func(args))
    except VaultError as exc:
        print(f"vault error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
