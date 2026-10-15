"""F4: the source of a local script the command runs, as a code-verified fact.

`python reproduce_issue.py` says nothing about what it does; the file does.
When the command runs a local script file, code reads that file and:

1. runs the same deterministic checks over its content that inline code
   (`python -c`, heredocs) already gets: the human gates, the hard-deny
   patterns and the network-library check. This can only ADD gates. A
   hard-deny pattern found inside a file becomes a human gate (ask), not a
   deny: file content includes names such as `def shutdown(self)` that the
   denylist was never written for, and the human must still be able to say
   yes.
2. when no gate fired, hands the content to the model as `script_source`,
   with a header naming the file, its sha256 and size. Secret-looking values
   are replaced with `<secret TYPE MASKED>` labels first. When the content carries an
   instruction marker (text addressed to an AI), the source is NOT sent as
   evidence; the passages around the markers go into `untrusted_context`
   instead, as for any other content the agent read.

Eligibility (all must hold, per script; otherwise nothing changes):
  - the command runs it as `python|python3|py <file>.py`, `bash|sh <file>.sh`,
    `node <file>.js|.mjs|.cjs` or `ruby <file>.rb`, also after `cd <dir> &&`;
  - resolved against cwd (and the `cd`), symlinks resolved, it is inside
    project_root and is a regular file;
  - at most 64 KiB, UTF-8 text (no NUL byte).
The source is sent only when every script the command runs is eligible.

TOCTOU: the host runs the file after semgate decided. It can change in
between. Hosts with a post-tool event re-hash it after the run and record a
mismatch (agentfiles.record_post, ledger incident `script_changed`). That is
a record, not a prevention.

The source is data. Nothing in it is an instruction to semgate or the model.
"""
from __future__ import annotations

import dataclasses
import hashlib
import ntpath
import os
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from . import injection, shellparse, tooloutputs
from .secretfinder import label_secrets
from .envelope import Envelope

MAX_SCRIPT_BYTES = 64 * 1024
SOURCE_CONTEXT_CAP = 1500            # chars of marker passages added to untrusted_context

# go is here because `go run x.go` compiles and runs in one command; the "run"
# subcommand is dropped in invocations(). Rust/Java/.NET are not listed: they
# have no inline eval and no single-command run-from-source semgate parses, so
# reading their files is a separate feature (catastrophic.py notes this).
_EXT = {"python": (".py",), "py": (".py",), "pypy": (".py",), "bash": (".sh",), "sh": (".sh",),
        "node": (".js", ".mjs", ".cjs"), "ruby": (".rb",), "perl": (".pl", ".pm"), "go": (".go",)}
_KIND = {".py": "code", ".js": "code", ".mjs": "code", ".cjs": "code", ".rb": "code", ".sh": "shell",
         ".pl": "code", ".pm": "code", ".go": "code"}
# Flags after which no script file follows (the code comes from elsewhere).
_STOP = {"python": {"-c", "-m", "-"}, "py": {"-c", "-m", "-"}, "pypy": {"-c", "-m", "-"},
         "bash": {"-c", "-s", "-"}, "sh": {"-c", "-s", "-"},
         "node": {"-e", "--eval", "-p", "--print", "-"}, "ruby": {"-e", "-"}, "perl": {"-e", "-E", "-"}}
# Flags that take a value.
_VALUE = {"python": {"-W", "-X", "-Q"}, "py": {"-W", "-X"}, "pypy": {"-W", "-X"},
          "bash": {"-o", "-O", "--rcfile", "--init-file"}, "sh": {"-o"},
          "node": {"-r", "--require", "--import", "--loader", "--experimental-loader", "--env-file", "--inspect-port"},
          "ruby": {"-r", "-I", "-C", "-E"}, "perl": {"-I", "-M"}}

def _base(word: str) -> str:
    return word.replace("\\", "/").rsplit("/", 1)[-1].lower()


def _prog(word: str) -> str:
    b = _base(word)
    if b.endswith(".exe"):
        b = b[:-4]
    return b if b in _EXT else re.sub(r"[\d.]+$", "", b)


@dataclass(frozen=True)
class Invocation:
    interpreter: str
    path: str          # as written in the command
    cwd: str           # directory it is resolved against (after any `cd`)


def invocations(command: str, cwd: str) -> List[Invocation]:
    """Local script files the command runs through an interpreter."""
    out: List[Invocation] = []
    cur = cwd
    try:
        simples = shellparse.split_commands(command)
    except Exception:
        return out
    for simple in simples:
        argv = shellparse.effective_argv(simple.tokens)
        if not argv:
            continue
        head = _base(argv[0].value)
        if head in ("cd", "pushd") and len(argv) >= 2:
            target = argv[1].value
            if target and target != "-":
                cur = _join(cur, target)
            continue
        prog = _prog(argv[0].value)
        exts = _EXT.get(prog)
        if not exts:
            continue
        rest = argv[1:]
        if prog == "go":
            # only `go run <files>` executes; go build/test/vet do not run the code.
            if not rest or rest[0].value != "run":
                continue
            rest = rest[1:]
        stop, value = _STOP.get(prog, set()), _VALUE.get(prog, set())
        skip = False
        for tok in rest:
            v = tok.value
            if skip:
                skip = False
                continue
            if v in stop:
                break
            if v.startswith("-"):
                if v in value:
                    skip = True
                continue
            if v.lower().endswith(exts):
                out.append(Invocation(prog, v, cur))
            break
    return out


_WIN_ABS = re.compile(r"^([A-Za-z]:[\\/]|\\\\)")


def _flavor(ref: str):
    """Path rules for `ref`: POSIX for /..., Windows for C:\\... or UNC, else
    this machine's. Eval cases carry POSIX paths even when run on Windows."""
    if ref.startswith("/"):
        return posixpath
    if _WIN_ABS.match(ref):
        return ntpath
    return os.path


def _join(cwd: str, path: str) -> str:
    if path.startswith("~"):
        path = os.path.expanduser(path)
    absolute = path.startswith("/") or bool(_WIN_ABS.match(path))
    mod = _flavor(path if absolute else (cwd or path))
    return mod.normpath(mod.join(cwd, path)) if cwd else mod.normpath(path)


@dataclass(frozen=True)
class ScriptFile:
    path: str          # absolute path (resolved)
    rel: str           # relative to project_root, "/" separators
    content: str
    sha256: str
    size: int
    kind: str          # "code" or "shell"
    run_cwd: str = ""   # the folder the command runs it in (collect sets it; relative paths in it resolve here)


def _text(data: bytes) -> Optional[str]:
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


class LocalWorkspace:
    """Reads script files from this machine's filesystem."""

    synthetic = False

    def is_dir(self, path: str, follow_links: bool = True) -> Optional[bool]:
        """S6: is `path` (linkplace.norm form: "/" separators, "~" for home)
        an existing folder on this machine? With follow_links=False (ln -n),
        a link to a folder is not a folder. A stat only; nothing is read."""
        try:
            real = os.path.expanduser(path) if path.startswith("~") else path
            if not os.path.isabs(real):
                return None
            if not follow_links and os.path.islink(real):
                return False
            return os.path.isdir(real)
        except (OSError, ValueError):
            return None

    @staticmethod
    def _inside_root(path: str, project_root: str, allow_equal: bool) -> Optional[str]:
        """The resolved path when it is inside the resolved project_root."""
        try:
            full = os.path.realpath(path)
            root = os.path.realpath(os.path.expanduser(project_root))
        except (OSError, ValueError):
            return None
        nfull, nroot = os.path.normcase(full), os.path.normcase(root)
        if nfull == nroot:
            return full if allow_equal else None
        return full if nfull.startswith(nroot.rstrip(os.sep) + os.sep) else None

    def entry(self, path: str, project_root: str) -> str:
        """testrun.py: "file", "dir" or "" (missing, or outside project_root
        after resolving links). A stat only; nothing is read."""
        if not path or not project_root or not os.path.isabs(path):
            return ""
        full = self._inside_root(path, project_root, allow_equal=True)
        try:
            if full is None:
                return ""
            if os.path.isfile(full):
                return "file"
            return "dir" if os.path.isdir(full) else ""
        except (OSError, ValueError):
            return ""

    def list_files(self, folder: str, project_root: str, recursive: bool = True, limit: int = 5000,
                   prune: Any = None) -> Tuple[List[str], bool]:
        """testrun.py: file paths under `folder` (as given, not resolved),
        sorted, at most `limit` entries visited; (paths, complete). Folders
        for which prune(name) is true and links to folders are not entered."""
        if not folder or not os.path.isabs(folder) or self._inside_root(folder, project_root, True) is None:
            return [], False
        out: List[str] = []
        seen = 0
        try:
            for dirpath, dirnames, filenames in os.walk(folder, followlinks=False):
                dirnames[:] = sorted(d for d in dirnames if not (prune and prune(d)))
                for name in sorted(filenames):
                    seen += 1
                    if seen > limit:
                        return out, False
                    out.append(os.path.join(dirpath, name))
                if not recursive:
                    break
        except OSError:
            return out, False
        return out, True

    def tool_program(self, path: str) -> str:
        """testrun.py: the resolved path of the program file `path` (a PATH
        folder joined with a program name), or "". A stat only."""
        try:
            if not os.path.isabs(path) or not os.path.isfile(path):
                return ""
            return os.path.realpath(path)
        except (OSError, ValueError):
            return ""

    def tool_file(self, path: str, max_bytes: int = 4096) -> Optional[str]:
        """testrun.py: a small toolchain file next to a program on PATH (the
        Go VERSION and go.env files), outside the project. Its text is not
        sent to the model; the caller keeps only a validated value."""
        try:
            if not os.path.isabs(path) or not os.path.isfile(path):
                return None
            with open(path, "rb") as handle:
                data = handle.read(max_bytes + 1)
        except (OSError, ValueError):
            return None
        return _text(data) if len(data) <= max_bytes else None

    def read(self, path: str, cwd: str, project_root: str) -> Tuple[Optional[ScriptFile], str]:
        if not project_root or not cwd:
            return None, "no cwd or project_root"
        raw = os.path.join(cwd, os.path.expanduser(path))
        if not os.path.isabs(raw):
            return None, "relative cwd"
        full = os.path.realpath(raw)
        root = os.path.realpath(os.path.expanduser(project_root))
        nfull, nroot = os.path.normcase(full), os.path.normcase(root)
        if nfull == nroot or not nfull.startswith(nroot.rstrip(os.sep) + os.sep):
            return None, "outside project_root (after resolving symlinks)"
        try:
            if not os.path.isfile(full):
                return None, "not a regular file"
            size = os.path.getsize(full)
            if size > MAX_SCRIPT_BYTES:
                return None, f"larger than {MAX_SCRIPT_BYTES} bytes"
            with open(full, "rb") as handle:
                data = handle.read(MAX_SCRIPT_BYTES + 1)
        except OSError as exc:
            return None, f"unreadable: {type(exc).__name__}"
        if len(data) > MAX_SCRIPT_BYTES:
            return None, f"larger than {MAX_SCRIPT_BYTES} bytes"
        text = _text(data)
        if text is None:
            return None, "not UTF-8 text"
        ext = os.path.splitext(full)[1].lower()
        return ScriptFile(path=full, rel=os.path.relpath(full, root).replace("\\", "/"), content=text,
                          sha256=hashlib.sha256(data).hexdigest(), size=len(data), kind=_KIND.get(ext, "code")), ""


class SyntheticWorkspace:
    """Serves file content from an eval case instead of the filesystem.
    `files` maps absolute paths to content; `dirs` lists folders that exist
    (the folders above each file exist too). Marked synthetic in manifests."""

    synthetic = True

    def __init__(self, files: Mapping[str, str], dirs: Iterable[str] = ()) -> None:
        self.files = {str(k): str(v) for k, v in (files or {}).items()}
        from . import linkplace
        known = set()
        for d in dirs or ():
            n = linkplace.norm(str(d))
            if n:
                known.add(n)
        for f in self.files:
            n = linkplace.norm(f)
            while n and linkplace.parent(n) != n:
                n = linkplace.parent(n)
                known.add(n)
        self.dirs = frozenset(known)

    def is_dir(self, path: str, follow_links: bool = True) -> Optional[bool]:
        """S6: is `path` (linkplace.norm form) a folder in this workspace?"""
        return path in self.dirs

    def entry(self, path: str, project_root: str) -> str:
        """testrun.py: "file", "dir" or "" for a path inside project_root."""
        if not path or not project_root:
            return ""
        mod = _flavor(path)
        full, root = mod.normpath(path), mod.normpath(project_root)
        if full != root and not full.startswith(root.rstrip("/\\") + mod.sep):
            return ""
        if full in self.files:
            return "file"
        from . import linkplace
        return "dir" if (full in self.dirs or linkplace.norm(full) in self.dirs) else ""

    def list_files(self, folder: str, project_root: str, recursive: bool = True, limit: int = 5000,
                   prune: Any = None) -> Tuple[List[str], bool]:
        """testrun.py: the workspace files under `folder`, sorted."""
        if self.entry(folder, project_root) != "dir":
            return [], False
        mod = _flavor(folder)
        prefix = mod.normpath(folder).rstrip("/\\") + mod.sep
        out: List[str] = []
        for p in sorted(self.files):
            if not p.startswith(prefix):
                continue
            parts = p[len(prefix):].replace("\\", "/").split("/")
            if (not recursive and len(parts) > 1) or (prune and any(prune(x) for x in parts[:-1])):
                continue
            out.append(p)
        return out[:limit], len(out) <= limit

    def tool_program(self, path: str) -> str:
        """testrun.py: `path` when the case lists it as a file (no links here)."""
        full = _flavor(path).normpath(path) if path else ""
        return full if full in self.files else ""

    def tool_file(self, path: str, max_bytes: int = 4096) -> Optional[str]:
        """testrun.py: a toolchain file of the case (outside the project)."""
        full = _flavor(path).normpath(path) if path else ""
        text = self.files.get(full)
        return text if text is not None and len(text.encode("utf-8")) <= max_bytes else None

    def read(self, path: str, cwd: str, project_root: str) -> Tuple[Optional[ScriptFile], str]:
        if not project_root or not cwd:
            return None, "no cwd or project_root"
        full = _join(cwd, path)
        mod = _flavor(full)
        root = mod.normpath(project_root)
        if full == root or not full.startswith(root.rstrip("/\\") + mod.sep):
            return None, "outside project_root"
        if full not in self.files:
            return None, "not in the synthetic workspace"
        data = self.files[full].encode("utf-8")
        if len(data) > MAX_SCRIPT_BYTES:
            return None, f"larger than {MAX_SCRIPT_BYTES} bytes"
        if b"\x00" in data:
            return None, "not UTF-8 text"
        ext = mod.splitext(full)[1].lower()
        return ScriptFile(path=full, rel=mod.relpath(full, root).replace("\\", "/"), content=self.files[full],
                          sha256=hashlib.sha256(data).hexdigest(), size=len(data), kind=_KIND.get(ext, "code")), ""


def scrub(text: str) -> Tuple[str, int]:
    """Label detected secret values, preserving instruction-bearing occurrences."""
    cleaned, count, _ = label_secrets(text, keep=tooloutputs.carries_marker)
    return cleaned, count


def gate_texts(script: ScriptFile) -> Tuple[str, str]:
    """(text for hard-deny patterns, text for human gates), the same way
    inline code is treated: shell scripts are lexed like a command (data
    removed for gates, nested code extracted); other code is checked as text
    plus the shell strings it passes to os.system/subprocess/exec."""
    content = script.content
    if script.kind == "shell":
        nested = shellparse.extract_scripts(content)
        tail = ("\n" + "\n".join(nested)) if nested else ""
        return content + tail, shellparse.gate_view(content) + tail
    nested: List[str] = []
    for m in shellparse._PY_SHELL_STRINGS.finditer(content):
        inner = m.group(2).strip()
        if inner:
            nested.append(inner)
            nested += shellparse.extract_scripts(inner)
    tail = ("\n" + "\n".join(nested)) if nested else ""
    return content + tail, content + tail


def code_for_network_check(script: ScriptFile) -> List[str]:
    if script.kind == "shell":
        return shellparse.extract_scripts(script.content)
    return [script.content]


def marker_passages(script: ScriptFile, window: int = injection._SNIPPET, cap: int = SOURCE_CONTEXT_CAP,
                    text: Optional[str] = None) -> str:
    """Passages around instruction markers in the file, for untrusted_context.
    Empty when the file has no marker."""
    parts: List[str] = []
    total = 0
    text = script.content if text is None else text
    for marker in injection.INSTRUCTION_MARKERS:
        for m in marker.finditer(text):
            passage = " ".join(text[max(0, m.start() - window):m.end() + window].split())
            piece = f"[from script file {script.rel}] ...{passage}..."
            piece = piece[: max(0, cap - total)]
            if piece:
                parts.append(piece)
                total += len(piece)
            if total >= cap:
                return "\n".join(parts)
    return "\n".join(parts)


@dataclass
class ScriptEvidence:
    files: List[ScriptFile] = field(default_factory=list)
    skipped: List[Dict[str, str]] = field(default_factory=list)   # ineligible invocations: {path, reason}
    injection: bool = False
    source_text: str = ""          # what goes into state["script_source"] ("" = nothing sent)
    context_text: str = ""         # marker passages for untrusted_context
    redactions: int = 0
    scrub_failed: bool = False

    @property
    def found(self) -> bool:
        return bool(self.files or self.skipped)

    def record(self, sent: bool) -> Dict[str, Any]:
        return {
            "files": [{"path": f.path, "rel": f.rel, "sha256": f.sha256, "size": f.size} for f in self.files],
            "skipped": list(self.skipped),
            "redactions": self.redactions,
            "scrub_failed": self.scrub_failed,
            "injection": self.injection,
            "sent": bool(sent),
        }


def collect(envelope: Envelope, workspace: Any) -> ScriptEvidence:
    """Find and read the scripts the command runs. Never raises."""
    ev = ScriptEvidence()
    command = envelope.action.arguments.get("command")
    if workspace is None or not isinstance(command, str) or not command.strip():
        return ev
    env = envelope.environment
    cwd = env.cwd or env.project_root
    try:
        for inv in invocations(command, cwd):
            script, why = workspace.read(inv.path, inv.cwd, env.project_root)
            if script is None:
                ev.skipped.append({"path": inv.path, "reason": why})
            elif all(f.path != script.path for f in ev.files):
                ev.files.append(dataclasses.replace(script, run_cwd=inv.cwd))
    except Exception as exc:  # a reader bug must not change the decision path
        ev.skipped.append({"path": "", "reason": f"error: {type(exc).__name__}"})
        return ev
    if not ev.files:
        return ev
    bodies = []
    try:
        for f in ev.files:
            body, n = scrub(f.content)
            bodies.append(body)
            ev.redactions += n
    except Exception:
        ev.scrub_failed = True
        return ev
    contexts = [marker_passages(f, text=body) for f, body in zip(ev.files, bodies)]
    ev.injection = any(contexts)
    if ev.injection:
        ev.context_text = "\n".join(c for c in contexts if c)[:SOURCE_CONTEXT_CAP]
        return ev
    if ev.skipped:
        return ev                   # evidence only when every script the command runs was read
    sections = []
    for f, body in zip(ev.files, bodies):
        sections.append(f"checked by code: current content of {f.rel}, sha256 {f.sha256[:12]}, {f.size} bytes\n{body}")
    ev.source_text = "\n\n".join(sections)
    return ev
