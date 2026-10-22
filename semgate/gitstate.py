"""Git state as a structural fact: can the files a command overwrites or
deletes be brought back with git?

The model sees only the command text, so it cannot know whether
`config/settings.json` is committed, has unsaved work, or is not in git at
all. Code can, in milliseconds, so code decides it (the same principle as
path-scope checks: structural facts come from rules, never from the model).

Used by the judge only when a `GitFacts` object is passed in (the hooks do
this when `git_facts` is enabled in their config); without it the judge
stays pure. Read-only: it runs `git status` / `git ls-files`, never anything
that changes the repository.

States, per target path:
  clean      tracked, no uncommitted change      -> recoverable (git restore)
  missing    does not exist yet                  -> recoverable (a new file)
  dirty      tracked, with uncommitted changes   -> the uncommitted part is lost
  untracked  exists, not in git                  -> lost
  agent_created  untracked, but the agent created it in this session through
             an action semgate saw run, its content is unchanged since
             (re-hashed now) and a snapshot of it exists -> recoverable
             (from the snapshot; see agentfiles.py). Only with an
             AgentFiles store and a host session id.
  ignored    matched by .gitignore               -> lost (often data or secrets)
  outside    not inside the repository           -> lost
  nogit      no repository here                  -> lost
  unknown    no fact for this path (SyntheticFacts in evals only) -> not
             recoverable, but not reported as a loss either
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple
from . import proc

RECOVERABLE = frozenset({"clean", "missing", "agent_created"})

# Redirect sinks that write nothing to disk.
_DEV_SINKS = re.compile(r"^/dev/(null|stdout|stderr|fd/\d+)$")

# Commands whose arguments are deleted, and commands whose LAST argument is
# overwritten. Flags (-x, --x, /x for cmd.exe) are skipped.
_DELETE_VERBS = {"rm", "del", "erase", "rd", "rmdir", "remove-item", "ri", "unlink", "shred"}
_DEST_VERBS = {"mv", "cp", "move", "copy", "move-item", "copy-item", "mi", "cpi", "install"}
_PS_PATH_FLAGS = {"-path", "-literalpath", "-filepath", "-destination"}
_SEGMENT_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")
_REDIRECT = re.compile(r"(?<![0-9&>])>(?!>)\s*([^\s|;&<>]+)")          # `> file`, not `>>` (append) and not `2>`
_TEE = re.compile(r"\btee\b(?![^|;&]*\s-a\b)\s+([^\s|;&]+)")
_SED_I = re.compile(r"\bsed\b[^|;&]*\s-i\S*\s+(?:'[^']*'|\"[^\"]*\"|\S+)\s+([^\s|;&]+)")
_PS_WRITE = re.compile(r"\b(set-content|out-file|clear-content)\b[^|;&]*?(?:-(?:literal)?path|-filepath)?\s+['\"]?([^\s'\"|;&\-][^\s'\"|;&]*)", re.I)
_PY_OPEN_W = re.compile(r"open\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"][wx]")
_GIT_DISCARD = re.compile(r"\bgit\s+(?:checkout\b[^|;&]*?\s--\s+|restore\s+)([^|;&]+)")


def _tokens(segment: str) -> List[str]:
    try:
        return shlex.split(segment, posix=False)
    except ValueError:
        return segment.split()


def _strip(tok: str) -> str:
    return tok.strip().strip("'\"")


def write_targets(command: str) -> List[str]:
    """Paths the command would overwrite or delete. Conservative: when a
    command's shape is not recognised, it contributes no target (the other
    layers still judge it)."""
    targets: List[str] = []
    for m in _REDIRECT.finditer(command):
        targets.append(m.group(1))
    for rx in (_TEE, _SED_I, _PY_OPEN_W):
        targets += [m.group(1) for m in rx.finditer(command)]
    for m in _PS_WRITE.finditer(command):
        targets.append(m.group(2))
    for m in _GIT_DISCARD.finditer(command):
        targets += [t for t in _tokens(m.group(1)) if not t.startswith("-")]
    for segment in _SEGMENT_SPLIT.split(command):
        toks = _tokens(segment)
        if not toks:
            continue
        verb = toks[0].lower()
        if verb == "sudo" and len(toks) > 1:
            toks, verb = toks[1:], toks[1].lower()
        args: List[str] = []
        skip_next = False
        for t in toks[1:]:
            low = t.lower()
            if skip_next:
                skip_next = False
                continue
            if low in _PS_PATH_FLAGS:
                continue
            if low.startswith("-") or (low.startswith("/") and len(low) <= 3 and verb in {"del", "erase", "rd", "rmdir", "move", "copy"}):
                if low in {"-t", "--target-directory"}:
                    skip_next = False
                continue
            args.append(t)
        if verb in _DELETE_VERBS:
            targets += args
        elif verb in _DEST_VERBS and len(args) >= 2:
            targets.append(args[-1])
            if verb in {"mv", "move", "move-item", "mi"}:
                targets += args[:-1]   # the source disappears from its place
    out: List[str] = []
    for t in targets:
        t = _strip(t)
        if t and t not in out and t not in {".", "&1", "/dev/null", "nul", "$null"} and not t.startswith("$") and not _DEV_SINKS.match(t):
            out.append(t)
    return out


@dataclass(frozen=True)
class TargetState:
    path: str
    state: str

    @property
    def recoverable(self) -> bool:
        return self.state in RECOVERABLE


class GitFacts:
    """Answers "can git bring these files back?" for one working directory.
    Every git call has a short timeout; any failure reports the path as
    'nogit', which is treated as not recoverable (fail closed)."""

    def __init__(self, timeout: float = 3.0, *, agent_files: "Optional[Any]" = None,
                 session_id: str = "", project_root: str = "") -> None:
        """`agent_files` (an agentfiles.AgentFiles), `session_id` (from the
        host event, never from the command) and `project_root` enable the
        `agent_created` state. Without all three, untracked stays untracked."""
        self.timeout = timeout
        self._root_cache: Dict[str, Optional[str]] = {}
        self.agent_files = agent_files
        self.session_id = session_id
        self.project_root = project_root

    def _untracked(self, path: str, full: str, raw: str) -> TargetState:
        if self.agent_files is not None and self.session_id and self.project_root:
            try:
                if self.agent_files.eligible(self.session_id, full, self.project_root, raw_path=raw):
                    return TargetState(path, "agent_created")
            except Exception:
                pass
        return TargetState(path, "untracked")

    def _git(self, cwd: str, *args: str) -> Tuple[int, str]:
        try:
            # Content comparisons may invoke clean/process drivers. Enumerate
            # their names without reading content, then disable every driver
            # for this read only. Never run a project helper as host evidence.
            env = dict(os.environ)
            env.pop("GIT_CONFIG", None)  # config-only redirect must not hide status configuration
            env["GIT_NO_LAZY_FETCH"] = "1"
            prefix = ["git", "--no-optional-locks", "--no-pager", "-c", "core.fsmonitor=false"]
            if args and args[0] == "status":
                config = proc.run([*prefix, "config", "--includes", "--null", "--name-only", "--get-regexp",
                                   r"^filter\..*\.(clean|smudge|process|required)$"], cwd=cwd,
                                  env=env, capture_output=True, text=True, timeout=self.timeout)
                if config.returncode not in (0, 1) or len(config.stdout) > 32768:
                    return 1, ""
                names = config.stdout.rstrip("\x00").split("\x00") if config.stdout else []
                if len(names) > 128 or any(not re.fullmatch(r"filter\..+\.(clean|smudge|process|required)", name)
                                           for name in names):
                    return 1, ""
                for driver in sorted({name.rsplit(".", 1)[0] for name in names}):
                    for option, value in (("clean", ""), ("smudge", ""), ("process", ""), ("required", "false")):
                        prefix += ["-c", driver + "." + option + "=" + value]
                prefix += ["-c", "status.submoduleSummary=false"]
                args = (args[0], "--ignore-submodules=all", *args[1:])
            p = proc.run([*prefix, *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=self.timeout)
            return p.returncode, p.stdout
        except Exception:
            return 1, ""

    def repo_root(self, cwd: str) -> Optional[str]:
        if cwd not in self._root_cache:
            code, out = self._git(cwd, "rev-parse", "--show-toplevel")
            self._root_cache[cwd] = os.path.normcase(os.path.realpath(out.strip())) if code == 0 and out.strip() else None
        return self._root_cache[cwd]

    def state(self, path: str, cwd: str) -> TargetState:
        if not cwd or not os.path.isdir(cwd):
            return TargetState(path, "nogit")
        root = self.repo_root(cwd)
        if root is None:
            return TargetState(path, "nogit")
        raw = os.path.join(cwd, os.path.expanduser(path))
        full = os.path.normcase(os.path.realpath(raw))
        if not (full == root or full.startswith(root.rstrip(os.sep) + os.sep)):
            return TargetState(path, "outside")
        if full == root:
            return TargetState(path, "outside")          # deleting the whole repo is never "recoverable"
        if not os.path.exists(full):
            return TargetState(path, "missing")
        rel = os.path.relpath(full, root)
        code, tracked = self._git(root, "ls-files", "--stage", "--", rel)
        if code != 0 or any(line.startswith("160000 ") for line in tracked.splitlines()):
            # A gitlink does not preserve its submodule's working bytes. Do
            # not recurse into another repository to manufacture recovery.
            return TargetState(path, "nogit")
        code, out = self._git(root, "status", "--porcelain", "--ignored", "--untracked-files=all", "--", rel)
        if code != 0:
            return TargetState(path, "nogit")
        lines = [l for l in out.splitlines() if l.strip()]
        if any(l.startswith("!!") for l in lines):
            return TargetState(path, "ignored")
        if any(l.startswith("??") for l in lines):
            return self._untracked(path, full, raw)
        if lines:
            return TargetState(path, "dirty")
        if tracked.strip():
            return TargetState(path, "clean")
        return self._untracked(path, full, raw)

    def assess(self, command: str, cwd: str) -> List[TargetState]:
        return [self.state(t, cwd) for t in write_targets(command)]


class SyntheticFacts:
    """Eval-only stand-in for GitFacts: the case lists the files the agent
    created in its trajectory and did not change since ({abs path: sha256}).
    Those targets are `agent_created`; every other target is `unknown` (no
    fact: never recoverable, never reported as a loss). No filesystem, no git.
    The facts are synthetic and are marked so in each set's manifest."""

    def __init__(self, agent_created: "Dict[str, str]", project_root: str) -> None:
        self.agent_created = {self._norm(k, ""): str(v) for k, v in (agent_created or {}).items()}
        self.project_root = self._norm(project_root, "") if project_root else ""

    @staticmethod
    def _norm(path: str, cwd: str) -> str:
        import ntpath
        import posixpath
        ref = path if (path.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", path)) else (cwd or path)
        mod = posixpath if ref.startswith("/") else ntpath
        return mod.normpath(mod.join(cwd, path)) if cwd else mod.normpath(path)

    def state(self, path: str, cwd: str) -> TargetState:
        full = self._norm(path, cwd or self.project_root)
        root = self.project_root
        inside = bool(root) and full != root and full.startswith(root.rstrip("/\\") + ("/" if root.startswith("/") else "\\"))
        if inside and full in self.agent_created:
            return TargetState(path, "agent_created")
        return TargetState(path, "unknown")

    def assess(self, command: str, cwd: str) -> List[TargetState]:
        return [self.state(t, cwd) for t in write_targets(command)]


# ---------- commit age: did the commits a history rewrite changes exist before the session? ----------
#
# Used by the code signal S1 (codesignals.py, policy router.code_signals).
# Read-only like GitFacts: it runs `git log`, never anything that changes the
# repository. Every rev given to git comes from the command text
# (agent-controlled), so it must pass _SAFE_REV: no leading "-", because git
# would read a rev like "--output=x" as an option.

_SAFE_REV = re.compile(r"^(?:[A-Za-z0-9_][A-Za-z0-9_./@{}~^:+\-]*|@(?:\{[A-Za-z0-9_\-]+\})?[~^0-9]*)$")
_LOG_CAP = 500   # commits read per check


def to_epoch(value: Any) -> Optional[float]:
    """Seconds since the epoch from an ISO-8601 string ("2026-09-23T10:00:00Z",
    fractions and offsets allowed) or a number (seconds, or milliseconds when
    larger than 1e11). None when it cannot be read."""
    from datetime import datetime, timezone
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        v = float(value)
        return v / 1000.0 if v > 1e11 else v
    text = str(value).strip()
    if not text:
        return None
    if re.fullmatch(r"\d+(?:\.\d+)?", text):
        return to_epoch(float(text))
    m = re.match(r"^(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)(\.\d+)?(Z|z|[+-]\d\d:?\d\d)?$", text)
    if not m:
        return None
    zone = m.group(3) or "+00:00"
    zone = "+00:00" if zone in ("Z", "z") else (zone if ":" in zone else zone[:3] + ":" + zone[3:])
    try:
        dt = datetime.fromisoformat(m.group(1).replace(" ", "T") + (m.group(2) or "") + zone)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


@dataclass(frozen=True)
class HistoryVerdict:
    """before   at least one changed commit is older than the session start
    during   every changed commit was made in this session
    none     the command changes no existing commit (e.g. reset to a descendant)
    unknown  could not be checked (no session start, no git, unusual refs)"""
    state: str
    before: int = 0
    total: int = 0
    detail: str = ""


def _selection(kind: str, info: Mapping[str, Any]) -> Optional[List[str]]:
    """git log arguments that select the commits a rewrite changes, or None
    when they cannot be named safely."""
    revs = [str(r) for r in (info.get("revs") or ())]
    extra = [str(info[k]) for k in ("tracking", "source") if info.get(k)]
    if any(not _SAFE_REV.match(r) for r in revs + extra):
        return None
    if kind == "amend":
        return ["-1", "HEAD"]
    if kind == "reset":
        return [f"{revs[0]}..HEAD"] if revs else None
    if kind == "rebase":
        if info.get("root"):
            return ["HEAD"]
        upstream = revs[0] if revs else "@{upstream}"
        branch = revs[1] if len(revs) > 1 else "HEAD"
        return [f"{upstream}..{branch}"]
    if kind == "force_push":
        source = str(info.get("source") or "HEAD")
        tracking = str(info.get("tracking") or "@{upstream}")
        return [f"{source}..{tracking}"]
    if kind == "filter":
        return ["--max-parents=0", "HEAD"]      # the oldest commits of the rewritten history
    if kind == "update_ref":
        if info.get("stdin") or not revs:
            return None
        if info.get("delete") or len(revs) < 2:
            return ["-1", revs[0]]
        return [f"{revs[1]}..{revs[0]}"]
    return None


class GitHistory:
    """Answers "were the commits this rewrite changes made before the session
    started?" with `git log`. `session_start` is a value (ISO string or epoch)
    or a function returning one; it is called at most once, and only when a
    rewrite is seen. run_core passes the earliest of the first ledger entry
    semgate wrote for the session and the host transcript's first timestamp.
    A commit's time is its author date, which survives amend and rebase, so a
    commit made before the session and rewritten during it still counts as
    before (the conservative direction)."""

    def __init__(self, session_start: Any = None, timeout: float = 3.0) -> None:
        self._session_start = session_start
        self._start_cache: Optional[Tuple[Optional[float]]] = None
        self.timeout = timeout

    def session_start(self) -> Optional[float]:
        if self._start_cache is None:
            raw = self._session_start
            try:
                raw = raw() if callable(raw) else raw
            except Exception:
                raw = None
            self._start_cache = (to_epoch(raw),)
        return self._start_cache[0]

    def _git(self, cwd: str, *args: str) -> Tuple[int, str]:
        try:
            p = proc.run(["git", "-c", "core.fsmonitor=false", *args], cwd=cwd, capture_output=True, text=True,
                               timeout=self.timeout)
            return p.returncode, p.stdout
        except Exception:
            return 1, ""

    def check(self, kind: str, info: Mapping[str, Any], cwd: str) -> HistoryVerdict:
        start = self.session_start()
        if start is None:
            return HistoryVerdict("unknown", detail="session start unknown")
        if not cwd or not os.path.isdir(cwd):
            return HistoryVerdict("unknown", detail="working directory unknown")
        selection = _selection(kind, info)
        if selection is None:
            return HistoryVerdict("unknown", detail="the changed commits cannot be named")
        code, out = self._git(cwd, "log", f"-n{_LOG_CAP}", "--format=%at", *selection)
        if code != 0:
            return HistoryVerdict("unknown", detail="git log failed")
        times = [int(x) for x in out.split() if x.strip().isdigit()]
        if not times:
            # The local copy of the remote may be stale: a force push can still
            # overwrite commits it does not show.
            if kind == "force_push":
                return HistoryVerdict("unknown", detail="the remote-tracking ref shows no dropped commit; it may be stale")
            return HistoryVerdict("none", detail="no existing commit is changed")
        before = sum(1 for t in times if t < start)
        return HistoryVerdict("before" if before else "during", before=before, total=len(times))


class SyntheticHistory:
    """Eval-only stand-in for GitHistory: the case states whether the
    commit(s) a rewrite changes predate the session
    (envelope.environment.git_head_predates_session, derived from the
    trajectory by the generator). None means unknown. No git."""

    def __init__(self, predates: Optional[bool]) -> None:
        self.predates = predates

    def check(self, kind: str, info: Mapping[str, Any], cwd: str) -> HistoryVerdict:
        if self.predates is None:
            return HistoryVerdict("unknown", detail="synthetic: no fact")
        return HistoryVerdict("before" if self.predates else "during", detail="synthetic")
