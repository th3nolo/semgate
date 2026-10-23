"""Keyed fingerprints of secret values (HMAC-SHA256 with a per-install key).

Why keyed: a plain sha256 of a short secret (an 8-character password) can be
recovered by hashing guesses. An HMAC needs the key too, so a copy of
semgate's files without the key does not let anyone test a guess.

Key: 32 random bytes (secrets.token_bytes), in `<state dir>/fingerprint.key`
where the state dir is the folder of `ledger_file` (`~/.semgate/<host>/` for
`semgate init <host>`), or semgate.json `secret_exposures.key_file`. Created
on first use under the file's cross-process lock (filelock), as a temp file
with mode 0600 (POSIX; on Windows the folder's ACL applies) that is then
renamed into place, so a reader never sees half a key and two processes
never make two keys. Read once per process (cached by path).

A key file that cannot be read, or does not hold exactly 32 bytes, is moved
aside (`fingerprint.key.bad-<epoch>`) and a new key is created; the caller
records an incident. When no key can be read or created, `key_for` returns
(None, problem) and the caller works without a fingerprint.

Fingerprint text: `hmac-sha256:<key id>:<64 hex>`. The key id (first 8 hex
of sha256 of a label and the key) names the key without revealing it, so a
fingerprint made with another key is a different value, never a false match.
Records of the earlier format (`sha256` field, plain sha256 of the value)
stay readable: callers treat them as another namespace ("sha256:<hex>").
"""
from __future__ import annotations

import hashlib
import hmac
import os
import random
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from . import filelock

KEY_NAME = "fingerprint.key"
KEY_BYTES = 32
ALG = "hmac-sha256"

_cache: Dict[str, bytes] = {}
_cache_lock = threading.Lock()


class KeyUnavailable(Exception):
    """No key could be read or created (lock timeout, OS error)."""


def read_existing_key(path: Path) -> bytes:
    """Read-only lookup: never create, repair or use a cached former key."""
    try:
        with path.open("rb") as stream:
            data = stream.read(KEY_BYTES + 1)
    except OSError as exc:
        raise KeyUnavailable("key unavailable") from exc
    if len(data) != KEY_BYTES:
        raise KeyUnavailable("invalid key length")
    return data


def key_path(config: Mapping[str, Any]) -> Path:
    value = config.get("secret_exposures") if isinstance(config.get("secret_exposures"), Mapping) else {}
    if value.get("key_file"):
        return Path(os.path.expanduser(str(value["key_file"])))
    from .storepaths import state_path
    return Path(state_path(config, KEY_NAME))


def _cache_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def _write_new(path: Path) -> bytes:
    """A new random key at `path`: temp file (0600, exclusive create), fsync,
    rename. The caller holds the lock."""
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(KEY_BYTES)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{random.getrandbits(32):08x}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    fd = os.open(str(tmp), flags, 0o600)
    try:
        try:
            view = memoryview(key)
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        if os.name != "nt":
            os.chmod(str(tmp), 0o600)          # exact mode, whatever the umask
        os.replace(str(tmp), str(path))
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except OSError:
            pass
    return key


def load_key(path: Path, timeout: float = 0.0) -> Tuple[bytes, str]:
    """(key, note). `note` is "" for a key read or created normally, or says
    which unusable key file was moved aside. Raises KeyUnavailable."""
    ck = _cache_key(path)
    with _cache_lock:
        if ck in _cache:
            return _cache[ck], ""
    note = ""
    try:
        with filelock.exclusive(path, timeout):
            try:
                data = path.read_bytes()
            except FileNotFoundError:
                data = None
            except OSError as exc:
                data = b""
                note = f"key file unreadable ({type(exc).__name__})"
            if data is not None and len(data) == KEY_BYTES:
                key = data
            else:
                if data is not None:
                    aside = path.with_name(f"{path.name}.bad-{int(time.time())}")
                    if not note:
                        note = f"key file holds {len(data)} bytes, not {KEY_BYTES}"
                    os.replace(str(path), str(aside))
                    note += f"; moved aside to {aside.name}"
                key = _write_new(path)
    except filelock.LockTimeout as exc:
        raise KeyUnavailable(f"lock timeout: {exc}") from exc
    except OSError as exc:
        raise KeyUnavailable(f"{type(exc).__name__}: {exc}") from exc
    with _cache_lock:
        _cache.setdefault(ck, key)
        return _cache[ck], note


def key_for(config: Mapping[str, Any], timeout: float = 0.0) -> Tuple[Optional[bytes], str]:
    """(key, problem): the key and "" (or a note about a replaced key file),
    or (None, reason) when no key is usable. Never raises."""
    try:
        return load_key(key_path(config), timeout)
    except KeyUnavailable as exc:
        return None, str(exc)[:300]
    except Exception as exc:                    # never let a key problem stop the caller
        return None, f"{type(exc).__name__}: {exc}"[:300]


def key_id(key: bytes) -> str:
    return hashlib.sha256(b"semgate fingerprint key id\x00" + key).hexdigest()[:8]


def fingerprint(key: bytes, value: str) -> str:
    digest = hmac.new(key, value.encode("utf-8", "replace"), hashlib.sha256).hexdigest()
    return f"{ALG}:{key_id(key)}:{digest}"


def clear_cache() -> None:
    """Tests only: forget the keys read by this process."""
    with _cache_lock:
        _cache.clear()
