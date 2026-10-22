"""Inspect supported outgoing payloads locally, without executing an action."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
import re
import stat
from typing import Any, Dict, List, Mapping
from urllib.parse import unquote, urlsplit

from .envelope import Envelope
from .privacydata import InputUnsafe, MAX_TEXT, Minimizer

MAX_FILE_BYTES = 262144
MAX_FILES = 8
TEXT_FORMATS = frozenset((".txt", ".json", ".jsonl", ".csv", ".tsv", ".md", ".log"))
_NETWORK = re.compile(r"(?i)\b(?:curl|wget|scp|sftp|rsync|ssh|netcat|ncat|nc|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Send-MailMessage)\b|\bgit\s+push\b|https?://")
_SEND_TOOL = re.compile(r"(?i)(?:send|upload|publish|post|email|request|web_fetch|fetch|http)")
_URL = re.compile(r"https?://[^\s\"'<>]+", re.I)
_AT_FILE = re.compile(r"(?<![\w.+-])@(?:\"([^\"]+)\"|'([^']+)'|([^\s\"';|<>]+))")
_OPAQUE = re.compile(r"(?i)(?:\b(?:python[\d.]*|node|ruby|perl|bash|sh|pwsh|powershell)\s+|\b(?:eval|exec)\s*\()")
_INDIRECT = re.compile(r"(?i)(?:\$\(|`|\$[A-Za-z_{]|%[A-Za-z_][\w]*%|\b(?:base64|b64encode|gzip)\b|--config\b|(?:^|\s)-K(?:\s|$)|--data(?:-binary)?\s+[\"']?@-|--upload-file\s+-|(?:^|\s)-T\s*-)" )
_FILE_KEYS = frozenset(("file", "file_path", "filename", "attachments", "files", "attachment", "infile"))


@dataclass
class Inspection:
    outgoing: bool = False
    complete: bool = True
    problems: List[str] = field(default_factory=list)
    files: List[Dict[str, Any]] = field(default_factory=list)
    destinations: List[str] = field(default_factory=list)
    cleaner: Minimizer = field(default_factory=Minimizer, repr=False)
    snapshots: Dict[Path, str] = field(default_factory=dict, repr=False)
    payloads: Dict[Path, bytes] = field(default_factory=dict, repr=False)

    def problem(self, code: str) -> None:
        self.complete = False
        if code not in self.problems:
            self.problems.append(code)

    def record(self) -> Dict[str, Any]:
        return {"outgoing": self.outgoing, "complete": self.complete, "categories": dict(sorted(self.cleaner.counts.items())),
                "problems": list(self.problems), "files": list(self.files)}

    def unchanged(self) -> bool:
        for path, digest in self.snapshots.items():
            try:
                if path.is_symlink() or path.resolve(strict=True) != path or path.stat().st_size > MAX_FILE_BYTES:
                    return False
                with path.open("rb") as stream:
                    data = stream.read(MAX_FILE_BYTES + 1)
                if len(data) > MAX_FILE_BYTES or hashlib.sha256(data).hexdigest() != digest:
                    return False
            except (OSError, ValueError):
                return False
        return True


def _references(value: Any, key: str = "", depth: int = 0) -> List[str]:
    if depth > 20:
        raise InputUnsafe("privacy reference depth exceeded")
    if isinstance(value, Mapping):
        return [p for k, v in value.items() for p in _references(v, str(k).lower(), depth + 1)]
    if isinstance(value, (list, tuple)):
        return [p for v in value for p in _references(v, key, depth + 1)]
    if key in _FILE_KEYS and isinstance(value, str):
        return [value]
    return []


def inspect(envelope: Envelope) -> Inspection:
    result = Inspection()
    args = dict(envelope.action.arguments)
    text = json.dumps(args, ensure_ascii=False, default=str)
    command = str(args.get("command", ""))
    result.outgoing = bool(_NETWORK.search(command) or _SEND_TOOL.search(envelope.action.tool)
                           or any(k in args for k in ("url", "endpoint", "recipient", "recipients", "to")))
    # Opaque interpreters can hide network behavior. No execution or speculative
    # reading of arbitrary scripts: mark this first implementation incomplete.
    if _OPAQUE.search(command):
        result.outgoing = True
        result.problem("opaque_program")
    if not result.outgoing:
        return result
    if len(text) > MAX_TEXT:
        result.problem("payload_limit")
        return result
    try:
        result.cleaner.clean(args)
        # URL-encoded values are inspected too; never execute/decompress input.
        decoded = unquote(unquote(text))
        if decoded != text:
            result.cleaner.text(decoded)
    except InputUnsafe:
        result.problem("payload_limit")
        return result
    for match in _URL.finditer(text):
        try:
            host = urlsplit(match.group()).hostname
        except ValueError:
            host = None
        if host and host not in result.destinations:
            result.destinations.append(host)
    for key in ("to", "recipient", "recipients"):
        recipients = args.get(key, [])
        for recipient in recipients if isinstance(recipients, (list, tuple)) else [recipients]:
            if isinstance(recipient, str) and recipient not in result.destinations:
                result.destinations.append(recipient)
    if _INDIRECT.search(command) or ("|" in command and _NETWORK.search(command)):
        result.problem("indirect_payload")
    if re.search(r"(?i)\b(?:scp|sftp|rsync|ssh|git\s+push)\b", command):
        result.problem("unsupported_transport")
    references = _references(args)
    from .privacycommands import file_references
    command_files = file_references(command)
    references.extend(command_files.references)
    for problem in command_files.problems:
        result.problem(problem)
    # Non-curl tools retain conservative @file discovery. Curl has its own
    # grammar (an email or --form-string @value is not a file read).
    if not re.search(r"(?i)\bcurl(?:\.exe)?\b", command):
        references.extend(next(g for g in m.groups() if g is not None) for m in _AT_FILE.finditer(command))
    references = list(dict.fromkeys(references))
    if len(references) > MAX_FILES:
        result.problem("file_count_limit")
        return result
    root_text = envelope.environment.project_root
    for index, reference in enumerate(references):
        if not root_text:
            result.problem("no_project_root")
            continue
        if not reference or any(c in reference for c in ("$", "%", "*", "?")):
            result.problem("dynamic_file_reference")
            continue
        try:
            root = Path(root_text).resolve(strict=True)
            path = Path(reference)
            if not path.is_absolute():
                cwd = Path(envelope.environment.cwd or root)
                path = cwd / path
            if path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction()):
                result.problem("linked_file")
                continue
            path = path.resolve(strict=True)
            path.relative_to(root)
            prefixes = envelope.grant.allowed_path_prefixes
            if prefixes and not any(path == Path(prefix).resolve() or Path(prefix).resolve() in path.parents for prefix in prefixes):
                result.problem("file_outside_grant")
                continue
            if path.suffix.lower() not in TEXT_FORMATS:
                result.problem("unsupported_file_format")
                continue
            before = path.stat()
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE_BYTES:
                result.problem("file_size_or_type")
                continue
            with path.open("rb") as stream:
                data = stream.read(MAX_FILE_BYTES + 1)
            after = path.stat()
            if len(data) > MAX_FILE_BYTES or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                result.problem("file_changed_or_large")
                continue
            content = data.decode("utf-8-sig")
            if "\x00" in content:
                result.problem("binary_file")
                continue
            result.cleaner.text(content)
            if path.suffix.lower() == ".json":
                result.cleaner.clean(json.loads(content))
            elif path.suffix.lower() in (".csv", ".tsv"):
                import csv
                import io
                for row in csv.DictReader(io.StringIO(content), delimiter="\t" if path.suffix.lower() == ".tsv" else ","):
                    result.cleaner.clean(row)
            digest = hashlib.sha256(data).hexdigest()
            result.files.append({"source": f"file_{index + 1}", "bytes": len(data), "sha256": digest})
            result.snapshots[path] = digest
            result.payloads[path] = data
        except (OSError, ValueError, InputUnsafe, UnicodeError):
            result.problem("file_uninspectable")
    return result
