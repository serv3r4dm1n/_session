#!/usr/bin/env python3
"""Rendezvous between the static unlock page and the waiting runner.

The runner keeps its ephemeral RSA public key in the session link, so a relay
observer cannot substitute a key.  The browser wraps the vault key to that key
and the runner opens the vault.  Only ciphertext and public data reach the relay.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

try:
    from . import vault
except ImportError:  # running as a plain script
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import vault  # type: ignore[no-redef]

DEFAULT_RELAY = "https://ntfy.sh"
POLL_SECONDS = 10
MAX_ATTEMPTS = 50
USER_AGENT = "secure-session/1"


class SessionError(Exception):
    """Relay or session failure."""


def relay_for(work_dir: Path, explicit: str | None) -> str:
    if explicit:
        return explicit.rstrip("/")
    try:
        value = (work_dir / "relay").read_text(encoding="utf-8").strip()
        if value:
            return value.rstrip("/")
    except OSError:
        pass
    return os.environ.get("RELAY_URL", DEFAULT_RELAY).rstrip("/")


def topic_for(work_dir: Path) -> str:
    try:
        topic = (work_dir / "topic").read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SessionError("session is not initialized") from exc
    if not topic or any(character not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for character in topic):
        raise SessionError("invalid session topic")
    return topic


def publish(topic: str, payload: dict[str, Any], relay: str) -> str:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    last_error: Exception | None = None
    delays = (2, 5, 10, 20, 30)
    for attempt, delay in enumerate(delays):
        request = urllib.request.Request(
            f"{relay}/{topic}",
            data=body,
            method="POST",
            headers={"Content-Type": "text/plain; charset=utf-8", "User-Agent": USER_AGENT},
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace").strip()[:200]
            except Exception:
                pass
            last_error = SessionError(
                f"relay returned HTTP {exc.code}" + (f": {detail}" if detail else "")
            )
            if exc.code not in (408, 425, 429) and exc.code < 500:
                break
        except (urllib.error.URLError, OSError) as exc:
            last_error = exc
        else:
            try:
                return str(json.loads(raw.decode("utf-8")).get("id", ""))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return ""
        if attempt + 1 < len(delays):
            time.sleep(delay)
    raise SessionError(f"could not publish to the relay: {last_error}") from last_error


def status_best_effort(topic: str, payload: dict[str, Any], relay: str) -> None:
    try:
        publish(topic, payload, relay)
    except SessionError:
        pass


def fetch(topic: str, relay: str) -> list[dict[str, Any]]:
    query = urllib.parse.urlencode({"poll": "1", "since": "all"})
    request = urllib.request.Request(
        f"{relay}/{topic}/json?{query}",
        headers={"User-Agent": USER_AGENT},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return []
        raise SessionError("could not read from the relay") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise SessionError("could not read from the relay") from exc
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("event") == "message":
            rows.append(value)
    return rows


def message_json(row: dict[str, Any]) -> dict[str, Any] | None:
    body = row.get("message")
    if not isinstance(body, str):
        return None
    try:
        value = json.loads(body)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def rsa_generate(private_path: Path) -> tuple[str, str]:
    try:
        result = subprocess.run(
            [
                "openssl", "genpkey",
                "-algorithm", "RSA",
                "-pkeyopt", "rsa_keygen_bits:2048",
                "-out", str(private_path),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode:
            raise SessionError("could not create the session key")
        os.chmod(private_path, 0o600)
        public = subprocess.run(
            ["openssl", "pkey", "-in", str(private_path), "-pubout", "-outform", "DER"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout
    except FileNotFoundError as exc:
        raise SessionError("OpenSSL is required") from exc
    except subprocess.CalledProcessError as exc:
        raise SessionError("could not create the session key") from exc
    return base64.b64encode(public).decode("ascii"), vault.b64u(public)


def rsa_decrypt(private_path: Path, ciphertext: bytes) -> bytes:
    try:
        result = subprocess.run(
            [
                "openssl", "pkeyutl", "-decrypt",
                "-inkey", str(private_path),
                "-pkeyopt", "rsa_padding_mode:oaep",
                "-pkeyopt", "rsa_oaep_md:sha256",
                "-pkeyopt", "rsa_mgf1_md:sha256",
            ],
            input=ciphertext,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SessionError("OpenSSL is required") from exc
    if result.returncode or not result.stdout:
        raise SessionError("could not unwrap the session key")
    return result.stdout


def init_session(work_dir: Path, relay: str) -> str:
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(work_dir, 0o700)
    except OSError:
        pass
    topic = secrets.token_hex(16)
    (work_dir / "topic").write_text(topic + "\n", encoding="utf-8")
    (work_dir / "relay").write_text(relay + "\n", encoding="utf-8")
    (work_dir / "started").write_text(str(int(time.time())) + "\n", encoding="utf-8")
    private_path = work_dir / "private.pem"
    public_b64, public_url = rsa_generate(private_path)
    (work_dir / "public.b64").write_text(public_b64 + "\n", encoding="utf-8")
    (work_dir / "public.url").write_text(public_url + "\n", encoding="utf-8")
    publish(topic, {"t": "pub", "v": 1, "key": public_b64}, relay)
    status_best_effort(topic, {"t": "status", "v": 1, "state": "waiting"}, relay)
    return topic


def wait_for_key(work_dir: Path, vault_path: Path, timeout: int, relay: str) -> None:
    topic = topic_for(work_dir)
    private_path = work_dir / "private.pem"
    if not private_path.is_file():
        raise SessionError("session key is missing")
    deadline = time.time() + timeout
    seen: set[str] = set()
    attempts = 0
    print("Waiting for passphrase...", flush=True)
    while time.time() < deadline:
        try:
            rows = fetch(topic, relay)
        except SessionError:
            time.sleep(POLL_SECONDS)
            continue
        for row in rows:
            message_id = row.get("id")
            if not isinstance(message_id, str) or not message_id or message_id in seen:
                continue
            seen.add(message_id)
            message = message_json(row)
            if not message or message.get("t") != "key":
                continue
            attempts += 1
            attempt_id = str(message.get("id", ""))
            if attempts > MAX_ATTEMPTS:
                status_best_effort(topic, {"t": "status", "v": 1, "state": "locked"}, relay)
                raise SessionError("too many passphrase attempts")
            try:
                wrapped = vault.b64d(message.get("key"), "session key")
                key = rsa_decrypt(private_path, wrapped)
                vault.open_vault(vault_path, key=key)
            except Exception:
                status_best_effort(
                    topic,
                    {"t": "status", "v": 1, "state": "rejected", "id": attempt_id},
                    relay,
                )
                continue
            (work_dir / "vault.key").write_text(vault.b64u(key) + "\n", encoding="utf-8")
            try:
                os.chmod(work_dir / "vault.key", 0o600)
            except OSError:
                pass
            (work_dir / "accepted").write_text(attempt_id + "\n", encoding="utf-8")
            status_best_effort(
                topic,
                {"t": "status", "v": 1, "state": "accepted", "id": attempt_id},
                relay,
            )
            try:
                private_path.unlink()
            except OSError:
                pass
            print("Passphrase accepted.", flush=True)
            return
        time.sleep(POLL_SECONDS)
    status_best_effort(topic, {"t": "status", "v": 1, "state": "timeout"}, relay)
    raise SessionError("timed out waiting for the passphrase")


def publish_command(work_dir: Path, command_file: Path, relay: str) -> None:
    topic = topic_for(work_dir)
    try:
        key = vault.b64ud((work_dir / "vault.key").read_text(encoding="ascii").strip())
    except OSError as exc:
        raise SessionError("session key is missing") from exc
    try:
        command = command_file.read_bytes()
    except OSError as exc:
        raise SessionError("could not read the command") from exc
    if not command or len(command) > 32_768:
        raise SessionError("invalid command")
    sealed = vault.seal_bytes(
        key, command, vault.COMMAND_DOMAIN, fmt=vault.COMMAND_FORMAT
    )
    publish(topic, {"t": "cmd", "v": 1, "cmd": sealed}, relay)
    status_best_effort(topic, {"t": "status", "v": 1, "state": "ready"}, relay)


def publish_status(work_dir: Path, state: str, relay: str, attempt_id: str | None) -> None:
    topic = topic_for(work_dir)
    payload: dict[str, Any] = {"t": "status", "v": 1, "state": state}
    if attempt_id:
        payload["id"] = attempt_id
    status_best_effort(topic, payload, relay)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--relay", help="relay base URL")
    sub = parser.add_subparsers(dest="action", required=True)

    init = sub.add_parser("init", help="create a session and publish its public key")
    init.add_argument("--work-dir", required=True)

    wait = sub.add_parser("wait", help="wait for the browser to unlock the vault")
    wait.add_argument("--work-dir", required=True)
    wait.add_argument("--vault", required=True)
    wait.add_argument("--timeout", type=int, default=1800)

    command = sub.add_parser("publish-command", help="encrypt and publish the client command")
    command.add_argument("--work-dir", required=True)
    command.add_argument("--command-file", required=True)

    status = sub.add_parser("status", help="publish a session status")
    status.add_argument("--work-dir", required=True)
    status.add_argument("--state", required=True)
    status.add_argument("--id")

    return parser


def main() -> int:
    args = build_parser().parse_args()
    work_dir = Path(getattr(args, "work_dir", "."))
    relay = relay_for(work_dir, args.relay)
    try:
        if args.action == "init":
            topic = init_session(work_dir, relay)
            print(f"Session initialized: {topic}")
        elif args.action == "wait":
            wait_for_key(work_dir, Path(args.vault), args.timeout, relay)
        elif args.action == "publish-command":
            publish_command(work_dir, Path(args.command_file), relay)
            print("Encrypted command published.")
        elif args.action == "status":
            publish_status(work_dir, args.state, relay, args.id)
        return 0
    except SessionError as exc:
        print(f"session error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
