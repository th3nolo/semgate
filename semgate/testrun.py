"""Test-run facts (policy `router.test_run_facts`, off by default).

A test command says little about what runs: `npm test` runs whatever
package.json names, `pytest` imports every conftest.py it passes, `make
test` runs recipe lines. The judge cannot know that, so a test run the user
asked for was always asked (effect answer split between "reads" and "runs
code from outside the project"). Code reads what actually runs and gives it
to the model with the F4 script source (state key `script_source`, whose
meaning the effect and executes questions already state). The model still
decides; nothing here allows anything.

What is recognised (after `cd DIR &&`, env assignments and wrappers):
  npm test | npm run X | yarn X | pnpm X   the script string of package.json
      (and pre/post scripts), each line analysed again (depth 3): a local
      file it runs (`node e2e.js`) is read like F4, a JS test runner (jest,
      vitest, mocha, ava, jasmine) lists the test files it runs, another
      `npm run` is followed.
  make [TARGET]        the recipe lines of the target and of the targets it
      needs (make variables expanded when defined in the file).
  pytest | py.test | python -m pytest   the test files it collects inside
      the project (count and names), the conftest.py files it imports (their
      content: they run as code), the pytest configuration section.
  python -m unittest   the test files it collects.
  go test PKGS         the _test.go files of the packages.
  cargo test           the crate folder, its tests/ files and its build
      script (build.rs, content: it runs as code).
  tox [-e ENV]         the tox.ini sections of the environments (deps and
      commands); the commands are analysed again.
  nox                  noxfile.py (content: it runs as code).
Shell scripts F4 read (`bash run_tests.sh`) are analysed the same way.

With policy `router.test_run_build_facts` (off by default), go test and cargo
test also get a fact on what the build downloads and what runs while it
builds, with a one-line summary of what is closed and what is not:
  go test      go.mod (required modules, replace lines, go line), go.sum,
      vendor/modules.txt and the -mod mode, GOPROXY / GOFLAGS / GOTOOLCHAIN /
      CGO_ENABLED set in the command, go.work, cgo files and #cgo lines,
      //go:generate lines (go test does not run them), -toolexec and -exec
      programs (a local file is read like F4), the files go test writes.
  cargo test   Cargo.lock (crates from registries and git), --offline /
      --frozen / --locked / CARGO_NET_OFFLINE, the project's .cargo/config.toml
      (vendored sources, mirrors, net.offline, rustc-wrapper, runner), path and
      git dependencies, build.rs of the crates and of path dependencies inside
      the project, the project's proc-macro crates (content: they run inside
      the compiler), the target folder.
Rust code of the project that runs at build time and uses the network
(std::net, reqwest, Command::new("curl") ...) is the gate embedded_execution
(build_gates).

Deterministic checks (only add gates, never remove one):
  - every shell line from project configuration that the command runs
    (package.json scripts, Makefile recipes and $(shell)/!= assignments,
    tox commands) is checked exactly as if it were the command: hard-deny
    patterns deny (a package.json "test": "curl ... | sh" is denied), the
    human gates and the network gate ask;
  - every code file that runs (conftest.py, noxfile.py, build.rs, JS runner
    configs, local files the lines run) goes through the F4 file gates
    (rules.script_gate_hits: a deny pattern inside a file is an ask).

Without a workspace (no file access) only what the command itself shows is
stated, and the text says what was not read. Secret-looking values are
labeled (<secret TYPE MASKED>). Text with an instruction marker is not sent
as evidence; the passages around the markers go to untrusted_context.

The facts are data. Nothing in them is an instruction to semgate or the model.
"""
from __future__ import annotations

import configparser
import ast
import dataclasses
import hashlib
import json
import ntpath
import os
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import injection, scriptsource, shellparse
from .envelope import Envelope, ProposedAction, Trajectory
from .scriptsource import ScriptFile

MAX_DEPTH = 3                 # nested analysis: npm script -> npm run -> make ...
MAX_LINES = 60                # config lines checked per command
MAX_NAMES = 5                 # test file names shown
WALK_LIMIT = 5000             # directory entries visited per listing
SOURCE_CAP = 24 * 1024        # code file content sent (bytes of text); above it: names only
MAX_TEST_SOURCES = 16         # unittest inputs + local imports in the verified worker profile
LINE_SHOW = 300               # chars of one config line shown

_PY_PROGS = re.compile(r"^(?:python[\d.]*|py|pypy[\d.]*)$")
_JS_RUNNERS = ("jest", "vitest", "mocha", "ava", "jasmine")
_NPM_SCRIPT_SUBS = {"test": "test", "t": "test", "tst": "test", "start": "start"}
_NPM_RUN = {"run", "run-script", "rum", "urn"}
_YARN_BUILTINS = {"add", "audit", "autoclean", "bin", "cache", "check", "config", "create", "dedupe", "dlx", "exec",
                  "explain", "generate-lock-entry", "global", "help", "import", "info", "init", "install", "licenses",
                  "link", "list", "login", "logout", "node", "npm", "outdated", "owner", "pack", "patch",
                  "patch-commit", "plugin", "policies", "publish", "rebuild", "remove", "set", "stage", "tag", "team",
                  "unlink", "unplug", "up", "upgrade", "upgrade-interactive", "version", "versions", "why",
                  "workspace", "workspaces"}
_PNPM_BUILTINS = {"add", "audit", "bin", "config", "create", "dedupe", "deploy", "dlx", "env", "exec", "fetch",
                  "i", "import", "init", "install", "install-test", "it", "licenses", "link", "list", "ln", "ls",
                  "outdated", "pack", "patch", "patch-commit", "prune", "publish", "rb", "rebuild", "recursive",
                  "remove", "rm", "root", "server", "setup", "store", "un", "uninstall", "unlink", "up", "update",
                  "why"}
_PKG_VALUE_OPTS = {"--prefix", "--cwd", "-C", "--dir", "--loglevel", "--registry", "--userconfig", "--cache"}
_PKG_MULTI = {"-w", "--workspace", "--workspaces", "-ws", "--filter", "-F", "-r", "--recursive", "--include-workspace-root"}

_PYTEST_VALUE = {"-k", "-m", "-p", "-c", "-o", "-W", "-n", "--rootdir", "--confcutdir", "--basetemp",
                 "--deselect", "--ignore", "--ignore-glob", "--junitxml", "--junit-xml", "--tb", "--maxfail",
                 "--durations", "--import-mode", "--log-level", "--log-file", "--log-cli-level", "--cov-report",
                 "--cov-config", "--timeout", "--override-ini", "--capture", "--color", "--junit-prefix",
                 "--dist", "--numprocesses", "--rsyncdir", "--tx", "--reruns", "--randomly-seed", "--lfnf",
                 "--last-failed-no-failures", "--durations-min", "--config-file", "--inifile",
                 "--html", "--css", "--benchmark-json", "--hypothesis-seed", "--cov-fail-under", "--doctest-glob"}
_PYTEST_INFO = {"--version", "-V", "--help", "-h"}
_PY_TEST_FILE = re.compile(r"^(?:test_.*|.*_test)\.py$")
_UNITTEST_FILE = re.compile(r"^test.*\.py$")
_PRUNE_DIRS = {"node_modules", "build", "dist", "venv", "env", "__pycache__", "site-packages", "CVS", "_darcs",
               "{arch}", "target", "coverage", "vendor"}

_JS_EXT = r"\.(?:c|m)?[jt]sx?$"
_JS_TEST = re.compile(r"(?:^|/)__tests__/.+" + _JS_EXT + r"|\.(?:test|spec)" + _JS_EXT)
_VITEST_TEST = re.compile(r"\.(?:test|spec)" + _JS_EXT)
_AVA_TEST = re.compile(r"(?:^|/)(?:test|tests|__tests__)/.+\.[cm]?js$|(?:^|/)test-[^/]*\.[cm]?js$|\.(?:test|spec)\.[cm]?js$|^(?:src/|source/)?test\.[cm]?js$")
_JASMINE_TEST = re.compile(r"(?:^|/)spec/.*[sS]pec\.[cm]?js$")
_JS_CONFIGS = {
    "jest": ("jest.config.js", "jest.config.ts", "jest.config.mjs", "jest.config.cjs"),
    "vitest": ("vitest.config.ts", "vitest.config.js", "vitest.config.mts", "vitest.config.mjs", "vitest.config.cjs",
               "vite.config.ts", "vite.config.js", "vite.config.mts", "vite.config.mjs"),
    "mocha": (".mocharc.js", ".mocharc.cjs"),
    "ava": ("ava.config.js", "ava.config.cjs", "ava.config.mjs"),
    "jasmine": (),
}

_GO_VALUE = {"-run", "-bench", "-count", "-timeout", "-tags", "-cpu", "-parallel", "-coverprofile", "-o", "-exec",
             "-p", "-ldflags", "-gcflags", "-asmflags", "-mod", "-modfile", "-covermode", "-coverpkg", "-benchtime",
             "-skip", "-shuffle", "-cpuprofile", "-memprofile", "-blockprofile", "-mutexprofile", "-trace",
             "-outputdir", "-fuzz", "-fuzztime", "-list", "-vet", "-pkgdir", "-toolexec", "-overlay", "-C"}
_CARGO_VALUE = {"-p", "--package", "--manifest-path", "--features", "-F", "--target", "-j", "--jobs", "--test",
                "--bench", "--bin", "--example", "--exclude", "--profile", "--target-dir", "--color", "-Z",
                "--config", "--message-format"}
_MAKE_VALUE = {"-C", "-f", "--file", "--makefile", "--directory", "-I", "--include-dir", "-o", "--old-file",
               "-W", "--what-if", "--new-file", "--assume-new", "-l", "--load-average"}
_MAKE_STOP = {"--eval"}
_TOX_VALUE = {"-e", "--env", "-c", "--conf", "--workdir", "--root", "-x", "--override", "--installpkg",
              "--result-json", "--hashseed", "--discover", "-m", "--labels", "-f", "--factors", "--runner"}
_NOX_VALUE = {"-s", "--session", "--sessions", "-f", "--noxfile", "-p", "--python", "--pythons", "-t", "--tags",
              "-k", "--keywords", "--envdir", "--extra-python", "--extra-pythons", "--force-python", "-P"}


# ---------- paths ----------


def _mod(path: str):
    return scriptsource._flavor(path)


def _join(cwd: str, path: str) -> str:
    return scriptsource._join(cwd, path) if (cwd or path) else ""


def _norm_case(mod, path: str) -> str:
    return mod.normcase(path) if mod is ntpath else path


def inside(path: str, root: str, allow_equal: bool = False) -> bool:
    """Lexical: is `path` inside the folder `root` (both absolute)?"""
    if not path or not root:
        return False
    mod = _mod(root)
    p, r = _norm_case(mod, mod.normpath(path)), _norm_case(mod, mod.normpath(root))
    if p == r:
        return allow_equal
    return p.startswith(r.rstrip("/\\") + mod.sep)


def _rel(path: str, root: str) -> str:
    mod = _mod(root)
    try:
        return mod.relpath(path, root).replace("\\", "/")
    except ValueError:
        return path


def _dirname(path: str) -> str:
    return _mod(path).dirname(path)


def _where(folder: str, root: str) -> str:
    """"/w/p (the project folder)" / "/w/p/sub (inside the project folder)"."""
    if inside(folder, root, allow_equal=True):
        return f"{folder} (the project folder)" if not inside(folder, root) else f"{folder} (inside the project folder)"
    return f"{folder} (outside the project folder {root})"


# ---------- workspace access (LocalWorkspace / SyntheticWorkspace) ----------


def _entry(ws: Any, path: str, root: str) -> str:
    """"file", "dir" or "" for an absolute path inside the project."""
    if ws is None or not inside(path, root, allow_equal=True):
        return ""
    fn = getattr(ws, "entry", None)
    return fn(path, root) if fn is not None else ""


def _list(ws: Any, folder: str, root: str, recursive: bool = True) -> Tuple[List[str], bool]:
    """(absolute file paths under `folder`, complete). Pruned folders skipped."""
    fn = getattr(ws, "list_files", None)
    if ws is None or fn is None or not inside(folder, root, allow_equal=True):
        return [], False
    return fn(folder, root, recursive=recursive, limit=WALK_LIMIT, prune=_pruned)


def _pruned(name: str) -> bool:
    return name.startswith(".") or name in _PRUNE_DIRS or name.endswith(".egg") or name.endswith(".egg-info")


def _read(ws: Any, path: str, root: str) -> Tuple[Optional[ScriptFile], str]:
    if ws is None:
        return None, "no file access"
    return ws.read(path, _dirname(path) or root, root)


# ---------- evidence ----------


@dataclass
class ConfigLine:
    """A shell command line from project configuration that the command runs."""
    where: str          # "package.json scripts.test", "Makefile recipe of test", "tox.ini [testenv] commands"
    line: str
    cwd: str


@dataclass
class TestRunEvidence:
    facts: List[str] = field(default_factory=list)            # fact paragraphs
    lines: List[ConfigLine] = field(default_factory=list)
    files: List[ScriptFile] = field(default_factory=list)     # code that runs (gated, content sent)
    configs: List[ScriptFile] = field(default_factory=list)   # configuration read (package.json, Makefile, ...)
    skipped: List[Dict[str, str]] = field(default_factory=list)
    runners: List[str] = field(default_factory=list)
    injection: bool = False
    source_text: str = ""
    context_text: str = ""
    redactions: int = 0
    scrub_failed: bool = False
    build_gates: List[Tuple[str, str]] = field(default_factory=list)   # (gate class, matched): build-time code

    @property
    def found(self) -> bool:
        return bool(self.facts or self.lines or self.files or self.skipped)

    def record(self, sent: bool) -> Dict[str, Any]:
        return {
            "runners": list(self.runners),
            "files": [{"path": f.path, "rel": f.rel, "sha256": f.sha256, "size": f.size} for f in self.files],
            "configs": [{"path": f.path, "rel": f.rel, "sha256": f.sha256, "size": f.size} for f in self.configs],
            "lines": [{"where": x.where, "line": x.line[:LINE_SHOW]} for x in self.lines],
            "skipped": list(self.skipped),
            "redactions": self.redactions,
            "scrub_failed": self.scrub_failed,
            "injection": self.injection,
            "sent": bool(sent),
            **({"build_gates": [{"gate_class": c, "matched": m} for c, m in self.build_gates]} if self.build_gates else {}),
        }


class _Ctx:
    def __init__(self, ws: Any, root: str, known: Sequence[ScriptFile], build: bool = False,
                 path_env: Optional[str] = None, read_test_sources: bool = False) -> None:
        self.ws = ws
        self.root = root
        self.build = build            # router.test_run_build_facts
        self.path_env = path_env      # the agent's PATH (hooks) or a case's fake PATH; None in evals
        self.read_test_sources = read_test_sources
        self.ev = TestRunEvidence()
        self.known = {f.path for f in known}
        self.seen_files: set = set()
        self.seen_configs: Dict[str, ScriptFile] = {}
        self.seen_lines: set = set()
        self.seen_runs: set = set()
        # With file access, something that runs could not be read (or a cap
        # stopped the walk): the facts are then not sent (the F4 rule); the
        # gates still check what was read.
        self.incomplete = False

    def add_file(self, f: ScriptFile, run_cwd: str) -> bool:
        """A code file that runs. False when F4 already has it."""
        if f.path in self.known or f.path in self.seen_files:
            return False
        self.seen_files.add(f.path)
        self.ev.files.append(dataclasses.replace(f, run_cwd=run_cwd))
        return True

    def config(self, path: str) -> Tuple[Optional[ScriptFile], str]:
        if path in self.seen_configs:
            return self.seen_configs[path], ""
        f, why = _read(self.ws, path, self.root)
        if f is not None:
            self.seen_configs[path] = f
            self.ev.configs.append(f)
        return f, why

    def add_line(self, where: str, line: str, cwd: str) -> bool:
        key = (line.strip(), cwd)
        if not line.strip() or key in self.seen_lines:
            return False
        if len(self.ev.lines) >= MAX_LINES:
            if not self.incomplete:
                self.skip(where, f"more than {MAX_LINES} command lines; the rest was not checked")
            self.incomplete = True
            return False
        self.seen_lines.add(key)
        self.ev.lines.append(ConfigLine(where, line.strip(), cwd))
        return True

    def skip(self, what: str, why: str, incomplete: bool = False) -> None:
        self.ev.skipped.append({"path": what, "reason": why})
        if incomplete and self.ws is not None:
            self.incomplete = True

    def runner(self, name: str) -> None:
        if name not in self.ev.runners:
            self.ev.runners.append(name)


def _show(text: str, limit: int = 200) -> str:
    one = " ".join(text.split())
    return one if len(one) <= limit else one[: limit - 3] + "..."


def _names(paths: Sequence[str], base: str, complete: bool) -> str:
    rels = sorted(_rel(p, base) for p in paths)
    if not rels and complete:
        return "none found"
    shown = ", ".join(rels[:MAX_NAMES]) + (", ..." if len(rels) > MAX_NAMES else "")
    count = f"{len(rels)} file{'s' if len(rels) != 1 else ''}" if complete else f"at least {len(rels)} files (listing stopped)"
    return f"{count} ({shown})" if rels else count


def _sha(f: ScriptFile) -> str:
    return f"sha256 {f.sha256[:12]}, {f.size} bytes"


# ---------- the walk over shell text ----------


def _argv_list(simple: Any) -> List[str]:
    return scriptsource.offline_uv_argv([t.value for t in shellparse.effective_argv(simple.tokens)])


def _prog(word: str) -> str:
    b = word.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return b[:-4] if b.endswith((".exe", ".cmd")) else b


def _walk(ctx: _Ctx, text: str, cwd: str, depth: int, who: str) -> None:
    """Find test runs in shell text (a command, a config line, a shell script)."""
    if not text.strip():
        return
    if depth > MAX_DEPTH:
        ctx.skip(_show(text), f"nested deeper than {MAX_DEPTH} levels; not followed")
        ctx.incomplete = True
        return
    try:
        simples = shellparse.split_commands(text)
    except Exception:
        return
    cur = cwd
    exported: Dict[str, str] = {}
    for simple in simples:
        argv = _argv_list(simple)
        assigned = _assignments(simple, argv)
        if not argv:
            exported.update(assigned)          # `GOFLAGS=-mod=vendor; go test` in the same shell
            continue
        head = _prog(argv[0])
        if head == "export":
            exported.update(_assignments_in(argv[1:]))
            continue
        if head in ("cd", "pushd") and len(argv) >= 2:
            if argv[1] and argv[1] != "-":
                cur = _join(cur, argv[1])
            continue
        raw = text[simple.start:simple.end].strip() if 0 <= simple.start < simple.end <= len(text) else ""
        raw = raw.rstrip(";&|").strip()
        shown = _show(raw if raw and argv[0] in raw else " ".join(argv))   # as written (quotes kept)
        label = f"`{shown}`" if depth == 0 else f"{who} (`{shown}`)"
        key = (tuple(argv), cur)
        if key in ctx.seen_runs:
            continue
        ctx.seen_runs.add(key)
        try:
            _one(ctx, argv, cur, depth, label, {**exported, **assigned})
        except Exception as exc:  # a parser bug must not change the decision path
            ctx.skip(shown, f"error: {type(exc).__name__}")
            ctx.incomplete = True


_ASSIGN_WORD = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)


def _assignments_in(words: Sequence[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for w in words:
        m = _ASSIGN_WORD.match(w)
        if m:
            out[m.group(1)] = m.group(2)
    return out


def _assignments(simple: Any, argv: Sequence[str]) -> Dict[str, str]:
    """NAME=value words before the program (`GOPROXY=off go test`, `env X=1 cargo test`)."""
    words: List[str] = []
    for t in simple.tokens:
        if argv and t.value == argv[0]:
            break
        if not t.redirect and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t.raw):   # the name is not quoted: X="a b" counts
            words.append(t.value)
    return _assignments_in(words)


def _one(ctx: _Ctx, argv: List[str], cwd: str, depth: int, label: str, env: Optional[Dict[str, str]] = None) -> None:
    prog = _prog(argv[0])
    args = argv[1:]
    if prog in ("npm", "yarn", "pnpm"):
        _package_script(ctx, prog, args, cwd, depth, label)
    elif prog in ("make", "gmake", "mingw32-make"):
        _make(ctx, args, cwd, depth, label)
    elif prog in ("pytest", "py.test"):
        _pytest(ctx, args, cwd, label)
    elif _PY_PROGS.match(prog):
        mod, rest = _py_module(args)
        if mod in ("pytest", "py.test"):
            _pytest(ctx, rest, cwd, label)
        elif mod == "unittest":
            _unittest(ctx, rest, cwd, label)
        elif mod == "tox":
            _tox(ctx, rest, cwd, depth, label)
        elif mod == "nox":
            _nox(ctx, rest, cwd, label)
    elif prog == "go" and args[:1] == ["test"]:
        _go_test(ctx, args[1:], cwd, label, env or {})
    elif prog == "cargo" and args[:1] in (["test"], ["t"]):
        _cargo_test(ctx, args[1:], cwd, label, env or {})
    elif prog == "tox":
        _tox(ctx, args, cwd, depth, label)
    elif prog == "nox":
        _nox(ctx, args, cwd, label)
    elif prog in _JS_RUNNERS or (prog == "react-scripts" and args[:1] == ["test"]):
        _js_runner(ctx, "jest" if prog == "react-scripts" else prog, args[1:] if prog == "react-scripts" else args,
                   cwd, label)


def _py_module(args: Sequence[str]) -> Tuple[str, List[str]]:
    for i, a in enumerate(args):
        if a == "-m" and i + 1 < len(args):
            return args[i + 1].lower(), list(args[i + 2:])
        if a.startswith("-m") and len(a) > 2:
            return a[2:].lower(), list(args[i + 1:])
        if a in ("-c", "-") or not a.startswith("-"):
            return "", []
    return "", []


def _local_scripts(ctx: _Ctx, text: str, cwd: str, depth: int, who: str) -> None:
    """A local file that a config line runs through an interpreter: read like
    F4 (gates, content). A shell script is walked again."""
    for inv in scriptsource.invocations(text, cwd):
        full = _join(inv.cwd, inv.path)
        f, why = _read(ctx.ws, full, ctx.root)
        if f is None:
            ctx.skip(inv.path, why, incomplete=True)
            continue
        if ctx.add_file(f, inv.cwd) and f.kind == "shell":
            _walk(ctx, f.content, inv.cwd, depth + 1, f"{f.rel}")


# ---------- npm / yarn / pnpm ----------


def _package_script(ctx: _Ctx, prog: str, args: List[str], cwd: str, depth: int, label: str) -> None:
    run_cwd, rest, i = cwd, [], 0
    while i < len(args):
        a = args[i]
        if a in _PKG_MULTI or a.startswith(("--workspace=", "--filter=")):
            ctx.skip(label, "workspace or filter option: several packages")
            return
        if a in _PKG_VALUE_OPTS and i + 1 < len(args):
            if a in ("--prefix", "--cwd", "-C", "--dir"):
                run_cwd = _join(cwd, args[i + 1])
            i += 2
            continue
        if a.startswith(("--prefix=", "--cwd=", "--dir=")):
            run_cwd = _join(cwd, a.split("=", 1)[1])
            i += 1
            continue
        if a.startswith("-") and not rest:
            i += 1
            continue
        rest = args[i:]
        break
    if not rest:
        return
    sub, name, extra = rest[0].lower(), "", []
    if prog == "npm":
        if sub in _NPM_SCRIPT_SUBS:
            name, extra = _NPM_SCRIPT_SUBS[sub], rest[1:]
        elif sub in _NPM_RUN and len(rest) > 1:
            name, extra = rest[1], rest[2:]
        else:
            return
    else:
        builtins = _YARN_BUILTINS if prog == "yarn" else _PNPM_BUILTINS
        if sub in ("run", "run-script") and len(rest) > 1:
            name, extra = rest[1], rest[2:]
        elif sub in ("test", "t", "tst") and prog == "pnpm":
            name, extra = "test", rest[1:]
        elif sub in builtins or sub.startswith("-"):
            return
        else:
            name, extra = rest[0], rest[1:]
    ctx.runner(prog)
    pkg = _find_up(ctx, run_cwd, ("package.json",))
    if not pkg:
        ctx.skip(label, "no package.json found inside the project" if ctx.ws is not None else "no file access")
        return
    f, why = ctx.config(pkg)
    if f is None:
        ctx.skip(_rel(pkg, ctx.root), why, incomplete=True)
        return
    try:
        data = json.loads(f.content)
        scripts = data.get("scripts") or {}
        deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
    except (ValueError, AttributeError):
        ctx.skip(f.rel, "package.json is not valid JSON", incomplete=True)
        return
    if not isinstance(scripts, dict) or not isinstance(scripts.get(name), str):
        if prog != "npm" and name.lower() in _JS_RUNNERS and name.lower() in deps:
            _js_runner(ctx, name.lower(), extra, run_cwd, label)      # `yarn jest`: the installed bin
            return
        if prog == "npm" or name == "test":
            ctx.ev.facts.append(f"checked by code: {label} runs the \"{name}\" script of {f.rel} ({_sha(f)}), "
                                f"but {f.rel} defines no \"{name}\" script, so it runs no project code.")
        return
    pkg_dir = _dirname(pkg)
    order = [n for n in (f"pre{name}", name, f"post{name}") if isinstance(scripts.get(n), str)]
    lines = []
    for n in order:
        line = scripts[n] + ((" " + " ".join(extra)) if (n == name and extra) else "")
        lines.append((n, line))
    pre_post = [n for n in order if n != name]
    note = ("" if pre_post else f" {f.rel} defines no \"pre{name}\" or \"post{name}\" script.")
    if pre_post and prog == "pnpm":
        note = f" pnpm runs {' and '.join(pre_post)} only when its enable-pre-post-scripts setting is on."
    text = [f"checked by code: {label} runs the \"{name}\" script of {f.rel} ({_sha(f)}) in {_where(pkg_dir, ctx.root)}, "
            f"shell command lines:{note}"]
    for n, line in lines:
        text.append(f"  scripts.{n}: {line[:LINE_SHOW]}")
    ctx.ev.facts.append("\n".join(text))
    for n, line in lines:
        where = f"{f.rel} scripts.{n}"
        if ctx.add_line(where, line, pkg_dir):
            _walk(ctx, line, pkg_dir, depth + 1, f"scripts.{n}")
            _local_scripts(ctx, line, pkg_dir, depth, where)


def _find_up(ctx: _Ctx, start: str, names: Sequence[str]) -> str:
    """The first of `names` in `start` or a folder above it, inside the project."""
    if ctx.ws is None or not start:
        return ""
    mod = _mod(start)
    cur = mod.normpath(start)
    while inside(cur, ctx.root, allow_equal=True):
        for n in names:
            p = mod.join(cur, n)
            if _entry(ctx.ws, p, ctx.root) == "file":
                return p
        up = mod.dirname(cur)
        if up == cur:
            break
        cur = up
    return ""


# ---------- JS test runners ----------


def _js_runner(ctx: _Ctx, runner: str, args: List[str], cwd: str, label: str) -> None:
    ctx.runner(runner)
    if runner == "vitest" and args[:1] and args[0] in ("run", "watch", "dev", "related", "bench"):
        args = args[1:]
    pkg = _find_up(ctx, cwd, ("package.json",))
    base = _dirname(pkg) if pkg else cwd
    installed = ""
    if pkg:
        f, _ = ctx.config(pkg)
        try:
            data = json.loads(f.content) if f is not None else {}
            deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
        except (ValueError, AttributeError):
            deps = {}
        pkg_name = "jest" if runner == "jest" and "react-scripts" in deps and "jest" not in deps else runner
        if pkg_name in deps or (runner == "jest" and "react-scripts" in deps):
            installed = f"{runner}, a JavaScript test runner that {_rel(pkg, ctx.root)} lists as a dependency (its code was not read)"
    if not installed:
        installed = f"{runner}, a JavaScript test runner (not listed in a package.json of the project; its code was not read)"
    if ctx.ws is None:
        ctx.ev.facts.append(f"checked by code: {label} runs {installed}. The test files and its configuration were not read.")
        return
    positional, code_opts = _js_args(runner, args)
    files, complete = _list(ctx.ws, base, ctx.root)
    rels = [(p, _rel(p, base)) for p in files]
    if runner == "mocha" and not positional:
        test_dir = _mod(base).join(base, "test")
        files, complete = _list(ctx.ws, test_dir, ctx.root, recursive=False)
        picked = [p for p in files if re.search(r"\.[cm]?js$", p)]
    elif runner == "mocha":
        picked = [p for p, r in rels if any(_glob_match(x, r) for x in positional)]
    else:
        pattern = {"jest": _JS_TEST, "vitest": _VITEST_TEST, "ava": _AVA_TEST, "jasmine": _JASMINE_TEST}[runner]
        picked = [p for p, r in rels if pattern.search(r)]
        if positional:
            picked = [p for p in picked if any(_path_filter(x, _rel(p, base)) for x in positional)]
    where = _where(base, ctx.root)
    filt = f" (limited to paths matching {' '.join(positional)[:120]})" if positional and runner != "mocha" else ""
    text = (f"checked by code: {label} runs {installed}, in {where}. It runs the project's own test files inside the "
            f"project folder{filt}: {_names(picked, base, complete)}. Their content was not read.")
    configs = []
    named = [_join(cwd, x) for x in code_opts]
    for p in named + [_mod(base).join(base, n) for n in _JS_CONFIGS.get(runner, ())]:
        if p in named and not re.search(r"\.[cm]?[jt]sx?$", p):
            continue                       # --config x.json: data, not code
        if p in named and not inside(p, ctx.root):
            configs.append(f"{p} (outside the project folder, not read)")
            ctx.skip(p, "outside the project folder", incomplete=True)
            continue
        if _entry(ctx.ws, p, ctx.root) == "file":
            f, why = _read(ctx.ws, p, ctx.root)
            if f is None:
                ctx.skip(_rel(p, ctx.root), why, incomplete=True)
                configs.append(f"{_rel(p, ctx.root)} (not read: {why})")
            else:
                ctx.add_file(f, base)
                configs.append(f.rel)
    if configs:
        text += f" These files run as code when it starts (configuration or required modules; content below): {', '.join(configs)}."
    ctx.ev.facts.append(text)


# Options of the JS runners that take a value (the value is not a test path).
_JS_VALUE = {"--config", "-c", "--testPathPattern", "--testPathIgnorePatterns", "-t", "--testNamePattern",
             "--maxWorkers", "-w", "--reporters", "--reporter", "-R", "--coverageDirectory", "--outputFile",
             "--testTimeout", "--timeout", "--selectProjects", "--project", "--shard", "--rootDir", "--root", "--dir",
             "--roots", "--environment", "--env", "--testEnvironment", "--pool", "--grep", "-g", "--fgrep", "-f",
             "--ui", "--extension", "--ignore", "--exclude", "--require", "-r", "--file", "--spec",
             "--setupFiles", "--globals", "--mode", "--reporter-option", "--slow", "-s", "--retries", "--jobs", "-j",
             "--seed", "--sequence.seed", "--since"}
_JS_CODE_OPTS = {"--config", "-c", "--require", "-r", "--file", "--setupFiles"}


def _js_args(runner: str, args: Sequence[str]) -> Tuple[List[str], List[str]]:
    """(positional path arguments, local files named by options that load code)."""
    positional: List[str] = []
    code: List[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            positional.extend(args[i + 1:])
            break
        name, _, inline = a.partition("=")
        if a.startswith("-") and name in _JS_VALUE:
            value = inline if "=" in a else (args[i + 1] if i + 1 < len(args) else "")
            if name in _JS_CODE_OPTS and value and (value.startswith((".", "/")) or re.search(r"\.[cm]?[jt]sx?$", value)):
                code.append(value)
            if name == "--spec" and value:
                positional.append(value)
            i += 1 if "=" in a else 2
            continue
        if not a.startswith("-"):
            positional.append(a)
        i += 1
    return positional, code


def _glob_match(pattern: str, rel: str) -> bool:
    import fnmatch
    p = pattern[2:] if pattern.startswith("./") else pattern
    return fnmatch.fnmatch(rel, p) or rel == p or rel.startswith(p.rstrip("/") + "/")


def _path_filter(arg: str, rel: str) -> bool:
    try:
        return re.search(arg, rel) is not None
    except re.error:
        return arg in rel


# ---------- make ----------


_ASSIGN = re.compile(r"^\s*(?:(?:override|export|private)\s+)*([A-Za-z0-9_.\-]+)\s*(::?=|:::=|\?=|\+=|!=|=)\s*(.*)$")
_RULE = re.compile(r"^([^\s:=#][^:=#]*?)\s*(::?)(?!=)\s*(.*)$")
_INCLUDE = re.compile(r"^\s*-?(?:include|sinclude)\s+(.+)$")
_VAR_REF = re.compile(r"\$[({]([A-Za-z0-9_.\-]+)[)}]")


@dataclass
class _Makefile:
    rules: Dict[str, Tuple[List[str], List[str]]] = field(default_factory=dict)   # target -> (prereqs, recipe)
    patterns: List[Tuple[str, List[str], List[str]]] = field(default_factory=list)
    order: List[str] = field(default_factory=list)
    variables: Dict[str, str] = field(default_factory=dict)
    shell_lines: List[str] = field(default_factory=list)   # != assignments and $(shell ...) lines
    includes: List[str] = field(default_factory=list)


def parse_makefile(text: str, mk: Optional[_Makefile] = None) -> _Makefile:
    mk = mk or _Makefile()
    raw = text.replace("\r\n", "\n").split("\n")
    lines: List[str] = []
    buf = ""
    for line in raw:
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        lines.append(buf + line)
        buf = ""
    if buf:
        lines.append(buf)
    current: List[str] = []
    in_define = ""
    define_body: List[str] = []
    for line in lines:
        if in_define:
            if line.strip() == "endef":
                mk.variables[in_define] = "\n".join(define_body)
                if "$(shell" in "\n".join(define_body):
                    mk.shell_lines.extend(define_body)
                in_define, define_body = "", []
            else:
                define_body.append(line)
            continue
        if line.startswith("\t"):
            if current:
                for t in current:
                    target = mk.rules.get(t)
                    if target is not None:
                        target[1].append(line[1:])
                    for pat in mk.patterns:
                        if pat[0] == t:
                            pat[2].append(line[1:])
            continue
        stripped = line.split("#", 1)[0].rstrip() if "#" in line and "\\#" not in line else line.rstrip()
        if not stripped.strip():
            continue
        s = stripped.strip()
        if s.startswith("define "):
            in_define = s.split(None, 1)[1].split("=")[0].strip()
            continue
        if re.match(r"^(ifeq|ifneq|ifdef|ifndef|else|endif)\b", s):
            continue
        inc = _INCLUDE.match(s)
        if inc:
            mk.includes.extend(inc.group(1).split())
            current = []
            continue
        if "$(shell" in s or "${shell" in s:
            mk.shell_lines.append(s)
        # A variable name holds no ':' or space, so `target: prereq` and
        # `target: VAR = x` never match _ASSIGN.
        m = _ASSIGN.match(s)
        rule = None if m else _RULE.match(s)
        if m:
            name, op, value = m.group(1), m.group(2), m.group(3)
            if op == "!=":
                mk.shell_lines.append(value)
            if op == "+=" and name in mk.variables:
                mk.variables[name] += " " + value
            elif op == "?=" and name in mk.variables:
                pass
            else:
                mk.variables[name] = value
            current = []
            continue
        if rule:
            targets = rule.group(1).split()
            rest = rule.group(3)
            inline = ""
            if ";" in rest:
                rest, inline = rest.split(";", 1)
            prereqs = [p for p in rest.replace("|", " ").split() if p]
            # target-specific variable: `target: VAR = value`
            if _ASSIGN.match(rest.strip()) and "=" in rest:
                current = []
                continue
            current = targets
            for t in targets:
                if "%" in t:
                    mk.patterns.append((t, prereqs, [inline.strip()] if inline.strip() else []))
                    continue
                if t not in mk.rules:
                    mk.rules[t] = ([], [])
                    mk.order.append(t)
                mk.rules[t][0].extend(prereqs)
                if inline.strip():
                    mk.rules[t][1].append(inline.strip())
            continue
        current = []
    return mk


def expand_make(text: str, variables: Dict[str, str], depth: int = 0) -> str:
    """Expand $(VAR) / ${VAR} with the file's own values (not automatic
    variables, not functions); $(MAKE) is make; $$ is $."""
    if depth > 5:
        return text

    def sub(m: "re.Match[str]") -> str:
        name = m.group(1)
        if name == "MAKE":
            return "make"
        if name in variables:
            return expand_make(variables[name], variables, depth + 1)
        return m.group(0)

    out = _VAR_REF.sub(sub, text)
    return out.replace("$$", "$") if depth == 0 else out


def _recipe_line(line: str) -> str:
    s = line.strip()
    while s[:1] in ("@", "-", "+"):
        s = s[1:].lstrip()
    return s


def _make(ctx: _Ctx, args: List[str], cwd: str, depth: int, label: str) -> None:
    run_cwd, mfile, targets, overrides, i = cwd, "", [], {}, 0
    while i < len(args):
        a = args[i]
        if a in _MAKE_STOP or a.startswith("--eval"):
            ctx.skip(label, "make --eval")
            return
        if a in _MAKE_VALUE and i + 1 < len(args):
            if a in ("-C", "--directory"):
                run_cwd = _join(run_cwd, args[i + 1])
            elif a in ("-f", "--file", "--makefile"):
                mfile = args[i + 1]
            i += 2
            continue
        if a.startswith("-C") and len(a) > 2:
            run_cwd = _join(run_cwd, a[2:])
        elif a.startswith("--directory="):
            run_cwd = _join(run_cwd, a.split("=", 1)[1])
        elif a.startswith("-f") and len(a) > 2 and not a.startswith("--"):
            mfile = a[2:]
        elif a.startswith(("--file=", "--makefile=")):
            mfile = a.split("=", 1)[1]
        elif a == "-j" and i + 1 < len(args) and args[i + 1].isdigit():
            i += 1
        elif "=" in a and not a.startswith("-"):
            k, v = a.split("=", 1)
            overrides[k.strip()] = v
        elif not a.startswith("-"):
            targets.append(a)
        i += 1
    ctx.runner("make")
    if ctx.ws is None:
        return
    if mfile:
        path = _join(run_cwd, mfile)
    else:
        path = ""
        for n in ("GNUmakefile", "makefile", "Makefile"):
            p = _mod(run_cwd).join(run_cwd, n) if run_cwd else ""
            if p and _entry(ctx.ws, p, ctx.root) == "file":
                path = p
                break
    if not path:
        ctx.skip(label, "no Makefile found inside the project")
        return
    f, why = ctx.config(path)
    if f is None:
        ctx.skip(_rel(path, ctx.root), why, incomplete=True)
        return
    mk = parse_makefile(f.content)
    unread = []
    for inc in list(mk.includes):
        if "$" in inc or "*" in inc:
            unread.append(inc)
            ctx.skip(inc, "include with a variable or pattern; not read", incomplete=True)
            continue
        ipath = _join(_dirname(path), inc)
        g, gwhy = ctx.config(ipath)
        if g is None:
            unread.append(inc)
            ctx.skip(inc, gwhy, incomplete=True)
            continue
        parse_makefile(g.content, mk)
    variables = {**mk.variables, **overrides}
    goals = targets or ([t for t in mk.order if not t.startswith(".")][:1])
    if not goals:
        ctx.skip(f.rel, "no target")
        return
    reached: List[str] = []
    recipes: Dict[str, List[str]] = {}
    missing: List[str] = []

    def visit(t: str, level: int) -> None:
        if t in reached or level > 6 or len(reached) >= 40:
            return
        rule = mk.rules.get(t)
        recipe: List[str] = []
        prereqs: List[str] = []
        if rule is not None:
            prereqs, recipe = rule
        if not recipe:
            for pat, pre, rec in mk.patterns:
                rx = "^" + re.escape(pat).replace("%", "(.+)") + "$"
                m = re.match(rx, t)
                if m and rec:
                    stem = m.group(1)
                    recipe = [r.replace("$*", stem) for r in rec]
                    prereqs = prereqs + [p.replace("%", stem) for p in pre]
                    break
        if rule is None and not recipe:
            if level == 0:
                missing.append(t)
            return
        reached.append(t)
        recipes[t] = recipe
        for p in prereqs:
            visit(expand_make(p, variables), level + 1)

    for g in goals:
        visit(g, 0)
    if missing and not reached:
        ctx.ev.facts.append(f"checked by code: {label} names the target {', '.join(missing)}, which {f.rel} ({_sha(f)}) "
                            f"does not define as a rule.")
        return
    mk_dir = _dirname(path)
    text = [f"checked by code: {label} runs these recipe lines of {f.rel} ({_sha(f)}) in {_where(mk_dir, ctx.root)} "
            f"(make runs each line in a shell; make variables defined in the file are expanded):"]
    pending: List[Tuple[str, str, str]] = []
    for t in reached:
        needs = [p for p in (mk.rules.get(t, ([], []))[0]) if p in recipes]
        text.append(f"  {t}:" + (f" (first runs {' '.join(needs)})" if needs else ""))
        for r in recipes[t]:
            line = expand_make(_recipe_line(r), variables)
            if line:
                text.append(f"    {line[:LINE_SHOW]}")
                pending.append((f"{f.rel} recipe of {t}", line, f"the recipe of {t}"))
    if not pending:
        text.append("  (no recipe lines)")
    if mk.shell_lines:
        text.append(f"  {f.rel} also runs shell code while it is read: " + "; ".join(_show(x, 150) for x in mk.shell_lines[:3]))
    ctx.ev.facts.append("\n".join(text))
    for where, line, who in pending:
        if ctx.add_line(where, line, mk_dir):
            _walk(ctx, line, mk_dir, depth + 1, who)
            _local_scripts(ctx, line, mk_dir, depth, where)
    for sh in mk.shell_lines:
        ctx.add_line(f"{f.rel} shell assignment", expand_make(sh, variables), mk_dir)


# ---------- pytest / unittest ----------


def _pytest(ctx: _Ctx, args: List[str], cwd: str, label: str) -> None:
    if any(a in _PYTEST_INFO for a in args):
        return
    paths, plugins, pyargs, noconftest, i = [], [], False, False, 0
    while i < len(args):
        a = args[i]
        if a == "--":
            paths.extend(args[i + 1:])
            break
        if a == "-p" and i + 1 < len(args):
            plugins.append(args[i + 1])
            i += 2
            continue
        if a.startswith("-p") and len(a) > 2 and not a.startswith("--"):
            plugins.append(a[2:])
        elif a == "--pyargs":
            pyargs = True
        elif a == "--noconftest":
            noconftest = True
        elif a in _PYTEST_VALUE and "=" not in a:
            i += 2
            continue
        elif not a.startswith("-"):
            if a.split("::", 1)[0] not in paths:
                paths.append(a.split("::", 1)[0])
        i += 1
    ctx.runner("pytest")
    plugin_note = ""
    loaded = [p for p in plugins if not p.startswith("no:")]
    if loaded:
        plugin_note = (f" -p loads the plugin module{'s' if len(loaded) > 1 else ''} {', '.join(loaded)} "
                       f"(installed Python code, not read).")
    head = f"checked by code: {label} runs pytest, the Python test runner, in {_where(cwd, ctx.root)}."
    if pyargs:
        ctx.ev.facts.append(head + f" --pyargs: it collects tests from the installed Python packages named "
                                   f"{', '.join(paths) or '(none)'} (not read)." + plugin_note)
        return
    targets = [(p, _join(cwd, p)) for p in paths] or [(".", cwd)]
    outside = [p for p, full in targets if not inside(full, ctx.root, allow_equal=True)]
    if ctx.ws is None:
        where = ", ".join(p for p, _ in targets)
        loc = ("inside the project folder" if not outside else
               f"{', '.join(outside)} {'is' if len(outside) == 1 else 'are'} outside the project folder")
        what = "the current folder and its subfolders" if not paths else where
        ctx.ev.facts.append(head + f" It collects tests from {what}, {loc}." + plugin_note +
                            " The test files, conftest.py files and pytest configuration were not read.")
        return
    if outside:
        ctx.ev.facts.append(head + f" It collects tests from {', '.join(outside)}, outside the project folder "
                                   f"{ctx.root}; those files were not read." + plugin_note)
        return
    config_note, testpaths = _pytest_config(ctx, cwd)
    if not paths and testpaths:
        targets = [(p, _join(cwd, p)) for p in testpaths]
    found: List[str] = []
    complete = True
    dirs: List[str] = []
    absent: List[str] = []
    for p, full in targets:
        kind = _entry(ctx.ws, full, ctx.root)
        if kind == "file":
            found.append(full)
            dirs.append(_dirname(full))
        elif kind == "dir":
            files, done = _list(ctx.ws, full, ctx.root)
            complete = complete and done
            found.extend(x for x in files if _PY_TEST_FILE.match(_mod(x).basename(x)))
            dirs.append(full)
        else:
            absent.append(p)
    text = head + f" It runs the project's own test files inside the project folder: {_names(found, cwd, complete)}."
    text += " Their content was not read." if found else ""
    if absent:
        text += f" Not found: {', '.join(absent)[:200]}."
    text += plugin_note
    if noconftest:
        text += " --noconftest: pytest does not import conftest.py files."
    else:
        confs = _conftests(ctx, dirs)
        shown, unread = [], []
        for c in confs:
            f, why = _read(ctx.ws, c, ctx.root)
            if f is None:
                unread.append(f"{_rel(c, ctx.root)} ({why})")
                ctx.skip(_rel(c, ctx.root), why, incomplete=True)
            else:
                ctx.add_file(f, cwd)
                shown.append(f.rel)
        if shown:
            text += (f" pytest first imports these conftest.py files, which run as code (content below): "
                     f"{', '.join(shown)}.")
        if unread:
            text += f" conftest.py files that were not read: {', '.join(unread)}."
        if not shown and not unread:
            text += " No conftest.py file is in the folders pytest reads (conftest.py files run as code when pytest starts)."
    text += config_note
    ctx.ev.facts.append(text)


def _conftests(ctx: _Ctx, dirs: Sequence[str]) -> List[str]:
    """conftest.py in each folder from the project folder down to each test
    folder, and in every folder below a test folder."""
    out: List[str] = []
    for d in dirs:
        mod = _mod(d)
        cur = mod.normpath(d)
        chain = []
        while inside(cur, ctx.root, allow_equal=True):
            chain.append(cur)
            up = mod.dirname(cur)
            if up == cur:
                break
            cur = up
        for folder in reversed(chain):
            p = mod.join(folder, "conftest.py")
            if p not in out and _entry(ctx.ws, p, ctx.root) == "file":
                out.append(p)
        files, _ = _list(ctx.ws, d, ctx.root)
        for p in files:
            if mod.basename(p) == "conftest.py" and p not in out:
                out.append(p)
    return out[:20]


def _pytest_config(ctx: _Ctx, cwd: str) -> Tuple[str, List[str]]:
    """(" pytest configuration from X: ...", testpaths) from the first config
    file in cwd or a folder above it (inside the project)."""
    mod = _mod(cwd)
    cur = mod.normpath(cwd)
    while inside(cur, ctx.root, allow_equal=True):
        for name, section in (("pytest.ini", "pytest"), ("pyproject.toml", "tool.pytest.ini_options"),
                              ("tox.ini", "pytest"), ("setup.cfg", "tool:pytest")):
            p = mod.join(cur, name)
            if _entry(ctx.ws, p, ctx.root) != "file":
                continue
            f, why = ctx.config(p)
            if f is None:
                ctx.skip(_rel(p, ctx.root), why, incomplete=True)
                return f" pytest configuration {_rel(p, ctx.root)} was not read ({why}).", []
            body = _ini_section(f.content, section)
            if body is None:
                continue
            lines = [ln.strip() for ln in body.splitlines() if ln.strip() and not ln.strip().startswith(("#", ";"))]
            testpaths: List[str] = []
            for ln in lines:
                m = re.match(r"^testpaths\s*=\s*(.*)$", ln)
                if m:
                    testpaths = re.findall(r"[\w./\-]+", m.group(1))
            shown = "; ".join(lines)[:600]
            return f" pytest configuration from {f.rel} [{section}]: {shown or '(empty)'}.", testpaths
        up = mod.dirname(cur)
        if up == cur:
            break
        cur = up
    return "", []


def _ini_section(text: str, section: str) -> Optional[str]:
    """Body of `[section]` in an INI or TOML file, None when absent."""
    m = re.search(r"^\[" + re.escape(section) + r"\][ \t]*$", text, re.M)
    if not m:
        return None
    rest = text[m.end():]
    end = re.search(r"^\[", rest, re.M)
    return rest[: end.start()] if end else rest


def _local_python_imports(ctx: _Ctx, file: ScriptFile, cwd: str) -> List[str]:
    """Conservative local import candidates, read as data without importing.

    Includes package initializers and possible from-import submodules. This
    is source evidence, not a claim to resolve Python's dynamic import system.
    """
    tree = ast.parse(file.content)
    found = set()
    for node in ast.walk(tree):
        names = []
        base = cwd
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = _dirname(file.path)
                for _ in range(node.level - 1):
                    base = _dirname(base)
            module = node.module or ""
            names = ([module] if module else []) + [
                ".".join(p for p in (module, alias.name) if p)
                for alias in node.names if alias.name != "*"]
        for name in names:
            parts = name.split(".")
            if not all(p.isidentifier() for p in parts):
                continue
            for i in range(1, len(parts) + 1):
                package = _join(base, "/".join(parts[:i]) + "/__init__.py")
                if _entry(ctx.ws, package, ctx.root) == "file":
                    found.add(package)
            module_path = _join(base, "/".join(parts) + ".py")
            if _entry(ctx.ws, module_path, ctx.root) == "file":
                found.add(module_path)
    return sorted(found)


def _test_sources(ctx: _Ctx, paths: List[str], cwd: str, complete: bool) -> str:
    """Bounded test inputs and local imports; never a closed call graph."""
    if not ctx.read_test_sources:
        return " Their content was not read."
    if not complete or len(paths) > MAX_TEST_SOURCES:
        ctx.skip("unittest sources", "incomplete listing or too many direct test inputs", incomplete=True)
        return " Test-source inspection is incomplete."
    total, seen = 0, set()
    pending = sorted(set(paths))
    while pending:
        path = pending.pop(0)
        if path in seen:
            continue
        seen.add(path)
        if len(seen) > MAX_TEST_SOURCES:
            ctx.skip("unittest sources", "test inputs and local imports exceed the file bound", incomplete=True)
            break
        file, why = _read(ctx.ws, path, ctx.root)
        if file is None:
            ctx.skip(path, why, incomplete=True)
            continue
        total += file.size
        if total > SOURCE_CAP:
            ctx.skip("unittest sources", "test inputs and local imports exceed the source bound", incomplete=True)
            break
        ctx.add_file(file, cwd)
        try:
            pending.extend(p for p in _local_python_imports(ctx, file, cwd) if p not in seen)
        except (SyntaxError, ValueError, RecursionError):
            ctx.skip(file.rel, "Python imports could not be inspected", incomplete=True)
    return (" Test sources and statically named local imports are shown below. "
            "Dynamic imports, external dependencies and discovery hooks are not a closed call graph. "
            "Unittest's -q/--quiet and -v/--verbose flags change reporting verbosity, not the tested code or its permissions.")


def _unittest(ctx: _Ctx, args: List[str], cwd: str, label: str) -> None:
    ctx.runner("unittest")
    if any(a in ("-h", "--help") for a in args):
        return
    value_opts = {"-k", "-s", "--start-directory", "-p", "--pattern", "-t", "--top-level-directory"}
    positional, i = [], 0
    while i < len(args):
        if args[i] in value_opts:
            i += 2
            continue
        if not args[i].startswith("-"):
            positional.append(args[i])
        i += 1
    start, pattern, discover = ".", "test*.py", not positional or positional[0] == "discover"
    if discover:
        rest = args[args.index("discover") + 1:] if "discover" in args else list(args)
        pos: List[str] = []
        i = 0
        while i < len(rest):
            a = rest[i]
            if a in ("-s", "--start-directory") and i + 1 < len(rest):
                start = rest[i + 1]
                i += 2
                continue
            if a in ("-p", "--pattern") and i + 1 < len(rest):
                pattern = rest[i + 1]
                i += 2
                continue
            if a in ("-t", "--top-level-directory", "-k") and i + 1 < len(rest):
                i += 2
                continue
            if not a.startswith("-"):
                pos.append(a)
            i += 1
        if pos:
            start = pos[0]
        if len(pos) > 1:
            pattern = pos[1]
    head = f"checked by code: {label} runs unittest, the Python standard test runner, in {_where(cwd, ctx.root)}."
    if discover:
        folder = _join(cwd, start)
        if not inside(folder, ctx.root, allow_equal=True):
            ctx.ev.facts.append(head + f" It collects tests from {start}, outside the project folder {ctx.root}.")
            return
        if ctx.ws is None:
            ctx.ev.facts.append(head + f" It collects test files named {pattern} from {start}, inside the project "
                                       f"folder. The test files were not read.")
            return
        import fnmatch
        files, complete = _list(ctx.ws, folder, ctx.root)
        picked = [p for p in files if fnmatch.fnmatch(_mod(p).basename(p), pattern)]
        # Discovery imports packages (including their load_tests hooks) even
        # when their initializer does not match the test filename pattern.
        initializers = [p for p in files if _mod(p).basename(p) == "__init__.py"]
        ctx.ev.facts.append(head + f" It runs the project's own test files inside the project folder: "
                                   f"{_names(picked, cwd, complete)}." + _test_sources(ctx, picked + initializers, cwd, complete))
        return
    mods = [a for a in positional]
    paths = []
    for m in mods:
        if m.endswith(".py") or "/" in m:
            paths.append(m)
        else:
            parts = m.split(".")
            paths.append("/".join(parts[:-1] if len(parts) > 1 and parts[-1][:1].isupper() else parts) + ".py")
    if ctx.ws is None:
        ctx.ev.facts.append(head + f" It runs the test modules {', '.join(mods)[:200]}. The test files were not read.")
        return
    found = [_join(cwd, p) for p in paths if _entry(ctx.ws, _join(cwd, p), ctx.root) == "file"]
    ctx.ev.facts.append(head + f" It runs the test modules {', '.join(mods)[:200]}; project test files found: "
                               f"{_names(found, cwd, True)}." + _test_sources(ctx, found, cwd, len(found) == len(paths)))


# ---------- go / cargo ----------


def _go_test(ctx: _Ctx, args: List[str], cwd: str, label: str, env: Optional[Dict[str, str]] = None) -> None:
    pkgs, exec_prog, i = [], "", 0
    while i < len(args):
        a = args[i]
        if a == "-args":
            break
        if a in _GO_VALUE and i + 1 < len(args):
            if a == "-exec":
                exec_prog = args[i + 1]
            i += 2
            continue
        if a.startswith("-exec="):
            exec_prog = a.split("=", 1)[1]
        elif not a.startswith("-"):
            pkgs.append(a)
        i += 1
    ctx.runner("go test")
    pkgs = pkgs or ["."]
    head = f"checked by code: {label} runs the Go test runner in {_where(cwd, ctx.root)}: it builds the packages {' '.join(pkgs)[:200]} and runs their tests."
    if exec_prog:
        head += f" -exec runs each test binary through {exec_prog}."
    local = [p for p in pkgs if p == "." or p.startswith(("./", "../")) or p == "./..."]
    remote = [p for p in pkgs if p not in local]
    if remote:
        head += f" Packages named by import path ({' '.join(remote)[:120]}) were not checked."
    if ctx.ws is None:
        ctx.ev.facts.append(head + " The test files were not read.")
        if ctx.build:
            _go_build(ctx, args, cwd, label, env or {})
        return
    found: List[str] = []
    complete = True
    for p in local:
        recursive = p.endswith("/...")
        folder = _join(cwd, p[:-4] if recursive else p)
        if not inside(folder, ctx.root, allow_equal=True):
            head += f" {p} is outside the project folder {ctx.root}."
            continue
        files, done = _list(ctx.ws, folder, ctx.root, recursive=recursive)
        complete = complete and done
        found.extend(x for x in files if x.endswith("_test.go") and "/testdata/" not in x.replace("\\", "/"))
    ctx.ev.facts.append(head + f" The project's own test files inside the project folder: {_names(found, cwd, complete)}."
                               " Their content was not read.")
    if ctx.build:
        _go_build(ctx, args, cwd, label, env or {})


def _cargo_test(ctx: _Ctx, args: List[str], cwd: str, label: str, env: Optional[Dict[str, str]] = None) -> None:
    manifest, i = "", 0
    while i < len(args):
        a = args[i]
        if a == "--":
            break
        if a in _CARGO_VALUE and i + 1 < len(args):
            if a == "--manifest-path":
                manifest = args[i + 1]
            i += 2
            continue
        if a.startswith("--manifest-path="):
            manifest = a.split("=", 1)[1]
        i += 1
    ctx.runner("cargo test")
    head = f"checked by code: {label} runs cargo, the Rust build tool, in {_where(cwd, ctx.root)}: it builds the crate and runs its tests."
    if ctx.ws is None:
        ctx.ev.facts.append(head + " Build scripts (build.rs, which run as code during the build) and the test files were not read.")
        if ctx.build:
            _cargo_build(ctx, args, cwd, label, env or {}, "")
        return
    path = _join(cwd, manifest) if manifest else _find_up(ctx, cwd, ("Cargo.toml",))
    if not path or not inside(path, ctx.root):
        ctx.ev.facts.append(head + " No Cargo.toml was found inside the project folder.")
        if ctx.build:
            _cargo_build(ctx, args, cwd, label, env or {}, "")
        return
    f, why = ctx.config(path)
    if f is None:
        ctx.skip(_rel(path, ctx.root), why, incomplete=True)
        return
    crate_dirs = [_dirname(path)]
    members = re.search(r"^\[workspace\][^\[]*?members\s*=\s*\[([^\]]*)\]", f.content, re.M | re.S)
    note = ""
    if members:
        names = re.findall(r"\"([^\"]+)\"", members.group(1))
        literal = [m for m in names if "*" not in m]
        if len(literal) != len(names):
            ctx.skip(f.rel, "workspace members named with a pattern; not checked", incomplete=True)
        crate_dirs += [_join(_dirname(path), m) for m in literal]
    build_files, tests, complete = [], [], True
    for d in crate_dirs[:10]:
        custom = ""
        man = path if d == _dirname(path) else _mod(d).join(d, "Cargo.toml")
        if man != path:
            g, _ = ctx.config(man) if _entry(ctx.ws, man, ctx.root) == "file" else (None, "")
            text = g.content if g is not None else ""
        else:
            text = f.content
        m = re.search(r"^\s*build\s*=\s*\"([^\"]+)\"", text, re.M)
        if m:
            custom = m.group(1)
        b = _join(d, custom) if custom else _mod(d).join(d, "build.rs")
        if _entry(ctx.ws, b, ctx.root) == "file":
            bf, bwhy = _read(ctx.ws, b, ctx.root)
            if bf is None:
                ctx.skip(_rel(b, ctx.root), bwhy, incomplete=True)
                build_files.append(f"{_rel(b, ctx.root)} (not read: {bwhy})")
            else:
                ctx.add_file(bf, d)
                build_files.append(bf.rel)
        tests_dir = _mod(d).join(d, "tests")
        files, done = _list(ctx.ws, tests_dir, ctx.root)
        complete = complete and (done or _entry(ctx.ws, tests_dir, ctx.root) == "")
        tests.extend(x for x in files if x.endswith(".rs"))
    text = head + f" Crate manifest {f.rel} ({_sha(f)})."
    if build_files:
        text += f" Build scripts, which run as code during the build (content below): {', '.join(build_files)}."
    else:
        text += " No build script (build.rs) exists, so no project code runs during the build."
    text += f" Integration test files in tests/: {_names(tests, cwd, complete)}; unit tests are the #[test] functions in the crate's source files. Their content was not read." + note
    ctx.ev.facts.append(text)
    if ctx.build:
        _cargo_build(ctx, args, cwd, label, env or {}, path, crate_dirs[:10], build_files)


# ---------- go / cargo: what the build downloads and runs (router.test_run_build_facts) ----------
#
# A build can download code (Go modules, Go toolchains, crates) and run code
# while it builds (Rust build scripts and proc macros, cgo's C compiler,
# -toolexec, rustc wrappers). Code reads the files that decide this and says
# plainly what is closed and what is not. Code that runs at build time and is
# in the project goes through the F4 file gates (ctx.add_file) and, for Rust,
# a network check (build_gates). Nothing here allows anything.

GO_FILES_MAX = 400            # .go files read for cgo and //go:generate
VENDOR_CRATES_MAX = 200       # vendored crates checked for build scripts / proc macros
_GO_OUTPUT_FLAGS = ("-coverprofile", "-cpuprofile", "-memprofile", "-blockprofile", "-mutexprofile", "-trace", "-o",
                    "-outputdir")
_GO_GENERATE = re.compile(r"^//go:generate[ \t]+(.+)$", re.M)
_CGO_LINE = re.compile(r"^[ \t]*(?://[ \t]*)?#cgo[ \t]+(.+)$", re.M)
_GO_IMPORT_BLOCK = re.compile(r"^import\s*\((.*?)\)", re.M | re.S)
_RUST_MOD = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", re.M)
_NET_TOOLS = r"(?:curl|wget|nc|ncat|netcat|scp|sftp|ssh|rsync|ftp|telnet|socat)"
# Network use in Rust code that runs at build time (build.rs, proc macros).
_RUST_NETWORK = re.compile(
    r"\bstd::net\b|\bTcpStream\b|\bUdpSocket\b|\breqwest\b|\bureq\b|\bhyper::|\bcurl::|\bisahc\b|\battohttpc\b"
    r"|\bminreq\b|Command::new\(\s*\"(?:[^\"]*[/\\])?" + _NET_TOOLS + r"(?:\.exe)?\""
    r"|\"" + _NET_TOOLS + r"(?:\.exe)?\s")
_DEP_TABLE = re.compile(r"^(?:workspace\.|target\..+?\.)?(?:dev-|build-)?dependencies$")
_DEP_SUBTABLE = re.compile(r"^(?:workspace\.|target\..+?\.)?(?:dev-|build-)?dependencies\.([^.]+)$")


def _local_prog(word: str) -> bool:
    """A program named by a path (./x.sh, tools/wrap, /abs/x), not a PATH lookup."""
    w = word.replace("\\", "/")
    return "/" in w or bool(re.match(r"^[A-Za-z]:", w))


def _verb(items: Sequence[str]) -> str:
    return "imports" if len(items) == 1 else "import"


def _short(items: Sequence[str], limit: int = MAX_NAMES) -> str:
    return ", ".join(items[:limit]) + (", ..." if len(items) > limit else "")


def _prog_fact(ctx: _Ctx, value: str, base: str, source: str, what: str) -> str:
    """A program the build runs (-toolexec, -exec, rustc-wrapper, runner). A
    local file is read like F4 (gates, content below)."""
    prog = value.split()[0] if value.split() else value
    if not prog:
        return ""
    if not _local_prog(prog):
        return f"{source}: {what} it runs the installed program {prog} (not read)."
    full = _join(base, prog)
    f, why = _read(ctx.ws, full, ctx.root)
    if f is None:
        ctx.skip(prog, why, incomplete=True)
        return f"{source}: {what} it runs {prog}, which was not read ({why})."
    ctx.add_file(f, base)
    return f"{source}: {what} it runs {f.rel}, a file in the project folder (content below)."


# ---- Go ----


def _go_opts(args: Sequence[str]) -> Tuple[Dict[str, str], List[str]]:
    """(flags -> value, "" for a bool flag; package arguments)."""
    opts: Dict[str, str] = {}
    pkgs: List[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-args":
            break
        if not a.startswith("-"):
            pkgs.append(a)
            i += 1
            continue
        name, eq, val = a.partition("=")
        name = "-" + name.lstrip("-")
        if eq:
            opts[name] = val
        elif name in _GO_VALUE and i + 1 < len(args):
            opts[name] = args[i + 1]
            i += 2
            continue
        else:
            opts[name] = ""
        i += 1
    return opts, pkgs


def parse_gomod(text: str) -> Dict[str, Any]:
    """module, go, toolchain, require [(module, version)], replace [(old, new)]."""
    info: Dict[str, Any] = {"module": "", "go": "", "toolchain": "", "require": [], "replace": []}
    block = ""

    def entry(kw: str, rest: str) -> None:
        if kw == "require":
            parts = rest.split()
            if len(parts) >= 2:
                info["require"].append((parts[0].strip('"'), parts[1]))
        elif kw == "replace" and "=>" in rest:
            old, new = rest.split("=>", 1)
            if old.split() and new.split():
                info["replace"].append((old.split()[0].strip('"'), " ".join(new.split()).strip('"')))

    for raw in text.replace("\r\n", "\n").split("\n"):
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if block:
            if line == ")":
                block = ""
            else:
                entry(block, line)
            continue
        m = re.match(r"^(module|go|toolchain|require|replace|exclude|retract|tool|godebug|ignore)\b\s*(.*)$", line)
        if not m:
            continue
        kw, rest = m.group(1), m.group(2).strip()
        if rest == "(":
            block = kw
        elif kw in ("module", "go", "toolchain"):
            info[kw] = rest.strip('"')
        else:
            entry(kw, rest)
    return info


def _go_version(text: str) -> Tuple[int, ...]:
    m = re.match(r"^(?:go)?(\d+)\.(\d+)", text or "")
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def _imports_c(text: str) -> bool:
    if re.search(r"^import\s+\"C\"", text, re.M):
        return True
    return any(re.search(r"^\s*\"C\"\s*$", b, re.M) for b in _GO_IMPORT_BLOCK.findall(text))


def _go_release(text: str) -> Tuple[int, int, int]:
    m = re.match(r"^(?:go)?(\d+)\.(\d+)(?:\.(\d+))?", text or "")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)) if m else (0, 0, 0)


def _path_entries(path_env: str, root: str) -> List[str]:
    """The absolute folders of a PATH value, outside the project folder."""
    value = str(path_env or "")
    sep = ";" if (";" in value or re.match(r"^\s*\"?[A-Za-z]:", value)) else ":"
    out: List[str] = []
    for raw in value.split(sep):
        entry = raw.strip().strip('"')
        if not entry or "$" in entry or "%" in entry or not re.match(r"^(?:/|[A-Za-z]:[/\\])", entry):
            continue
        if root and inside(entry, root, allow_equal=True):
            continue                       # a program inside the project could claim any version
        if entry not in out:
            out.append(entry)
    return out


def go_installed(ws: Any, path_env: Optional[str], root: str = "") -> Tuple[str, str, str]:
    """(version "go1.23.1", its VERSION file, the GOTOOLCHAIN line of GOROOT/go.env)
    of the first go program on PATH; ("", "", "") when not found. Only stats
    and two small files next to the program; nothing runs."""
    if ws is None or not path_env or getattr(ws, "tool_program", None) is None:
        return "", "", ""
    for folder in _path_entries(path_env, root):
        mod = _mod(folder)
        for name in ("go", "go.exe"):
            real = ws.tool_program(mod.join(folder, name))
            if not real:
                continue
            if root and inside(real, root, allow_equal=True):
                return "", "", ""          # resolves into the project: its version is not trusted
            rmod = _mod(real)
            goroot = rmod.dirname(rmod.dirname(real))
            vfile = rmod.join(goroot, "VERSION")
            text = ws.tool_file(vfile) or ""
            m = re.match(r"^(go\d+\.\d+(?:\.\d+)?)\s*$", (text.splitlines() or [""])[0])
            if not m:
                return "", "", ""          # the go that runs has no readable version: not checked
            env_text = ws.tool_file(rmod.join(goroot, "go.env")) or ""
            tc = re.search(r"^GOTOOLCHAIN=([A-Za-z0-9.+]+)\s*$", env_text, re.M)
            return m.group(1), vfile, tc.group(1) if tc else ""
    return "", "", ""


def _go_toolchain_fact(ctx: _Ctx, want: str, tc: str) -> Tuple[str, str]:
    """(sentence, summary item) on whether go downloads a Go release for `want`."""
    if tc == "path":
        return ("Go toolchain: GOTOOLCHAIN=path in the command: go does not download another Go release.",
                "no Go toolchain download (GOTOOLCHAIN=path)")
    if tc and tc != "auto":
        return (f"Go toolchain: GOTOOLCHAIN={tc} in the command (go may use or download that Go release).",
                f"GOTOOLCHAIN={tc} in the command")
    have, where, default = go_installed(ctx.ws, ctx.path_env, ctx.root)
    if not have:
        why = "no PATH was given" if not ctx.path_env else "no go program with a VERSION file was found on PATH"
        return (f"Go toolchain: go.mod asks for {want}. When the installed Go is older (Go 1.21 or later, with "
                f"GOTOOLCHAIN not set to local), go first downloads the official {want} release, checked against "
                f"sum.golang.org. The installed Go version was not checked ({why}).",
                f"a Go {want} download is possible (installed Go version not checked)")
    if _go_release(have) >= _go_release(want):
        return (f"Go toolchain: the installed Go is {have} ({where}), not older than {want} in go.mod, so go does not "
                f"download another Go release.", f"no Go toolchain download (installed {have})")
    if _go_release(have) < (1, 21, 0):
        return (f"Go toolchain: the installed Go is {have} ({where}), older than {want} in go.mod; Go before 1.21 "
                f"does not download Go releases.", f"no Go toolchain download (installed {have})")
    if default == "local":
        return (f"Go toolchain: the installed Go is {have} ({where}), older than {want} in go.mod; its go.env sets "
                f"GOTOOLCHAIN=local, so go does not download another release (it stops with an error).",
                f"no Go toolchain download (installed {have}, GOTOOLCHAIN=local)")
    return (f"Go toolchain: the installed Go is {have} ({where}), older than {want} in go.mod, so go first downloads "
            f"the official {want} release, checked against sum.golang.org, unless GOTOOLCHAIN=local.",
            f"downloads the Go {want} release (installed {have} is older)")


def _go_skipped(rel: str) -> bool:
    """Go ignores testdata/ and files or folders starting with _ or ."""
    return any(p == "testdata" or p.startswith(("_", ".")) for p in rel.replace("\\", "/").split("/"))


def _go_build(ctx: _Ctx, args: List[str], cwd: str, label: str, env: Dict[str, str]) -> None:
    opts, pkgs = _go_opts(args)
    goflags = env.get("GOFLAGS", "").split()

    def setting(name: str) -> Tuple[Optional[str], str]:
        if f"-{name}" in opts:
            return opts[f"-{name}"], f"-{name} in the command"
        for w in goflags:
            n, eq, v = w.lstrip("-").partition("=")
            if n == name and eq:
                return v, "GOFLAGS in the command"
        return None, ""

    proxy_off = env.get("GOPROXY", "").strip() == "off"
    head = f"checked by code: what {label} downloads and runs while it builds"
    progs: List[str] = []
    for flag, what in (("toolexec", "for every compiler and linker step"), ("exec", "to start each test binary")):
        value, source = setting(flag)
        if value:
            progs.append(_prog_fact(ctx, value, cwd, f"-{flag} ({source})", what))
    progs = [p for p in progs if p]
    if ctx.ws is None:
        known = ([("GOPROXY=off in the command: go downloads nothing (no module and no Go toolchain).")]
                 if proxy_off else [])
        mod, source = setting("mod")
        if mod:
            known.append(f"-mod={mod} ({source}).")
        ctx.ev.facts.append(head + ": go.mod, go.sum, vendor/ and the .go files were not read (no file access). "
                            + " ".join(known + progs))
        return
    pkgs = pkgs or ["."]
    folders: List[Tuple[str, bool]] = []
    for p in pkgs:
        if not (p == "." or p.startswith(("./", "../"))):
            continue
        rec = p.endswith("/...")
        folder = _join(cwd, p[:-4] if rec else p)
        if inside(folder, ctx.root, allow_equal=True):
            folders.append((folder, rec))
    remote_pkgs = [p for p in pkgs if not (p == "." or p.startswith(("./", "../")))]
    start = folders[0][0] if folders else cwd
    modfile, _ = setting("modfile")
    gomod = _join(cwd, modfile) if modfile else _find_up(ctx, start, ("go.mod",))
    if not gomod or _entry(ctx.ws, gomod, ctx.root) != "file":
        ctx.ev.facts.append(head + f": no go.mod was found in {_rel(start, ctx.root)} or a folder above it inside the "
                            f"project folder, so what go downloads was not checked. " + " ".join(progs))
        return
    f, why = ctx.config(gomod)
    if f is None:
        ctx.skip(_rel(gomod, ctx.root), why, incomplete=True)
        return
    info = parse_gomod(f.content)
    mod_dir = _dirname(gomod)
    mod = _mod(mod_dir)
    gosum = gomod[:-4] + ".sum" if gomod.endswith(".mod") else mod.join(mod_dir, "go.sum")
    has_sum = _entry(ctx.ws, gosum, ctx.root) == "file"
    vendor_txt = _entry(ctx.ws, mod.join(mod_dir, "vendor", "modules.txt"), ctx.root) == "file"
    gowork = "" if env.get("GOWORK", "").strip() == "off" else _find_up(ctx, mod_dir, ("go.work",))
    ver = _go_version(info["go"])
    modv, msrc = setting("mod")
    if modv is None:
        if vendor_txt and ver >= (1, 14) and not gowork:
            modv, msrc = "vendor", "the default, because vendor/modules.txt exists and the go line is 1.14 or later"
        else:
            modv, msrc = "readonly", "the default"
    local_repl = {old: new for old, new in info["replace"] if new.startswith((".", "/")) or re.match(r"^[A-Za-z]:", new)}
    remote = [(m, v) for m, v in info["require"] if m not in local_repl]
    n = len(remote)
    s = "s" if n != 1 else ""
    summary = [f"{f.rel} present", ("go.sum present" if has_sum else
                                    "no go.sum (none needed: no required module)" if n == 0 else "no go.sum")]
    # downloads
    if proxy_off:
        dl = ("GOPROXY=off in the command: go downloads nothing (no module and no Go toolchain); a module missing from "
              "the module cache stops the build with an error.")
        summary.append("downloads nothing (GOPROXY=off)")
    elif modv == "vendor" and vendor_txt:
        dl = (f"-mod=vendor ({msrc}): go builds the required modules from vendor/ inside the project folder and "
              f"downloads no module.")
        summary.append("downloads no module (builds from vendor/)")
    elif modv == "vendor":
        dl = f"-mod=vendor ({msrc}), but vendor/modules.txt does not exist: go stops with an error before it builds."
        summary.append("downloads no module (-mod=vendor)")
    elif n == 0:
        dl = (f"{f.rel} requires no module" + (" other than ones replaced by local folders" if local_repl else "")
              + ", so go downloads no module.")
        summary.append("downloads no module (go.mod requires none)")
    else:
        dl = (f"{f.rel} requires {n} module{s} ({_short([m for m, _ in remote], 4)}). go downloads the ones not "
              f"already in its module cache (GOMODCACHE) from GOPROXY (default proxy.golang.org).")
        dl += (" go.sum pins their content hashes, and go checks every download against it." if has_sum else
               " go.sum does not exist, so the downloads are not pinned by hashes (go test stops with a "
               "\"missing go.sum entry\" error).")
        summary.append(f"may download {n} required module{s} into the module cache"
                       + (" (pinned by go.sum)" if has_sum else " (not pinned: no go.sum)"))
        if modv == "readonly":
            dl += f" -mod=readonly ({msrc}): go test does not change go.mod or go.sum."
    if modv == "mod" and not proxy_off:
        dl += f" -mod=mod ({msrc}): go may add or change requirements in go.mod and go.sum and download new versions."
        summary.append("-mod=mod may change go.mod and go.sum")
    tc = env.get("GOTOOLCHAIN", "").strip()
    want = info["toolchain"] or (("go" + info["go"]) if info["go"] else "")
    if tc == "local":
        dl += " GOTOOLCHAIN=local in the command: go does not download another Go release."
    elif want and not proxy_off and (info["toolchain"] or ver >= (1, 21)):
        text_tc, summary_tc = _go_toolchain_fact(ctx, want, tc)
        dl += " " + text_tc
        if summary_tc:
            summary.append(summary_tc)
    for old, new in info["replace"]:
        if old in local_repl:
            full = _join(mod_dir, new)
            where = ("inside the project folder" if inside(full, ctx.root, allow_equal=True)
                     else "outside the project folder, not read")
            dl += f" {f.rel} replaces {old} with the local folder {new} ({where}); go builds that code too."
        else:
            dl += f" {f.rel} replaces {old} with {new}: go downloads that instead."
    if gowork:
        dl += f" {_rel(gowork, ctx.root)} exists: go also builds the modules its use lines name (not checked)."
    # .go files: cgo and //go:generate
    go_files: List[str] = []
    complete = True
    for folder, rec in folders:
        files, done = _list(ctx.ws, folder, ctx.root, recursive=rec)
        complete = complete and done
        go_files.extend(x for x in files if x.endswith(".go") and not _go_skipped(_rel(x, folder)))
    cgo: List[str] = []
    cgo_lines: List[str] = []
    gen: List[Tuple[str, str]] = []
    unread = max(0, len(go_files) - GO_FILES_MAX)
    for x in go_files[:GO_FILES_MAX]:
        sf, _ = _read(ctx.ws, x, ctx.root)
        if sf is None:
            unread += 1
            continue
        if _imports_c(sf.content):
            cgo.append(sf.rel)
            cgo_lines.extend(" ".join(c.split()) for c in _CGO_LINE.findall(sf.content))
        gen.extend((sf.rel, g.strip()) for g in _GO_GENERATE.findall(sf.content))
    runs = ["Go has no build scripts: no project or module code runs while go builds. The code that runs is the test "
            "binaries: the packages, their _test.go files and the modules they import."] + progs
    if cgo and env.get("CGO_ENABLED", "").strip() == "0":
        runs.append(f"cgo: {_short(cgo)} {_verb(cgo)} \"C\", but CGO_ENABLED=0 in the command: go leaves those files out and "
                    f"runs no C compiler.")
        summary.append("no code runs at build time (Go has no build scripts; CGO_ENABLED=0)")
    elif cgo:
        runs.append(f"cgo: {_short(cgo)} {_verb(cgo)} \"C\", so go also runs the C compiler (CC, by default gcc or clang) on "
                    f"them and on the C files in their folders; go accepts only a fixed list of compiler and linker "
                    f"flags in #cgo lines." + (f" #cgo lines: {_show('; '.join(cgo_lines[:3]), 300)}." if cgo_lines else ""))
        summary.append("no project code runs at build time (Go has no build scripts); cgo runs the C compiler on "
                       + _short(cgo, 2))
    else:
        runs.append("No .go file of these packages imports \"C\" (cgo), so no C compiler runs.")
        summary.append("no code runs at build time (Go has no build scripts, no cgo)")
    if progs:
        summary.append("-toolexec/-exec runs another program (see below)")
    text = [head + f" (module {info['module'] or '(none)'}; {f.rel} {_sha(f)}):",
            "  summary: " + "; ".join(summary) + ".",
            "  downloads: " + dl,
            "  runs while building: " + " ".join(runs)]
    if gen:
        text.append(f"  //go:generate lines ({len(gen)}): "
                    + "; ".join(f"{r}: {_show(c, 150)}" for r, c in gen[:2]) + ("; ..." if len(gen) > 2 else "")
                    + ". go test does not run them; only the `go generate` command does.")
        summary.append(f"{len(gen)} //go:generate line{'s' if len(gen) != 1 else ''}, not run by go test")
        text[1] = "  summary: " + "; ".join(summary) + "."
    outs = [f"{k} {opts[k]}" for k in _GO_OUTPUT_FLAGS if opts.get(k)]
    if "-c" in opts:
        outs.append("-c (the test binary, in the current folder)")
    if "-fuzz" in opts:
        outs.append("-fuzz (failing inputs go to testdata/fuzz/ in the package folder)")
    text.append("  files written: " + ("It writes " + ", ".join(outs) + "." if outs else
                                       "go test writes no file in the project folder."))
    missing = []
    if unread or not complete:
        missing.append(f"{unread} .go file{'s' if unread != 1 else ''} not read" if unread else "the file listing stopped")
    if remote_pkgs:
        missing.append(f"packages named by import path ({_short(remote_pkgs, 3)})")
    if missing:
        text.append("  not checked for cgo and //go:generate: " + "; ".join(missing) + ".")
    ctx.ev.facts.append("\n".join(text))


# ---- Rust ----


def _toml_strip(line: str) -> str:
    """The line without a # comment (a # inside a string is kept)."""
    quote = ""
    for i, ch in enumerate(line):
        if quote:
            if ch == "\\" and quote == '"':
                continue
            if ch == quote:
                quote = ""
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "#":
            return line[:i]
    return line


def _toml_open(text: str) -> int:
    depth, quote, prev = 0, "", ""
    for ch in text:
        if quote:
            if ch == quote and prev != "\\":
                quote = ""
        elif ch in ("'", '"'):
            quote = ch
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        prev = ch
    return depth


def toml_entries(text: str) -> List[Tuple[str, str, str]]:
    """A TOML file as [(table, key, raw value)], line based: enough for Cargo
    manifests, Cargo config files and their inline tables; not a full TOML
    parser. Quotes around table and key names are removed; [[array]] tables
    are numbered (package.1, package.2 ...)."""
    out: List[Tuple[str, str, str]] = []
    table = ""
    key, buf = "", ""
    count: Dict[str, int] = {}
    for raw in text.splitlines():
        line = _toml_strip(raw).strip()
        if key:
            buf += " " + line
            if _toml_open(buf) <= 0:
                out.append((table, key, buf.strip()))
                key = ""
            continue
        if not line:
            continue
        m = re.match(r"^\[(\[?)\s*(.+?)\s*\]\]?$", line)
        if m:
            name = re.sub(r"\s*\.\s*", ".", m.group(2)).replace('"', "").replace("'", "")
            if m.group(1):
                count[name] = count.get(name, 0) + 1
                name = f"{name}.{count[name]}"
            table = name
            continue
        m = re.match(r"^((?:\"[^\"]*\"|'[^']*'|[A-Za-z0-9_\-.\s])+?)\s*=\s*(.*)$", line)
        if not m:
            continue
        k = re.sub(r"\s*\.\s*", ".", m.group(1).strip()).replace('"', "").replace("'", "")
        value = m.group(2).strip()
        if _toml_open(value) > 0:
            key, buf = k, value
            continue
        out.append((table, k, value))
    return out


def toml_flat(text: str) -> Dict[str, str]:
    """{"table.key": raw value} of toml_entries (the last one wins)."""
    return {(f"{t}.{k}" if t else k): v for t, k, v in toml_entries(text)}


def _tstr(raw: str) -> str:
    raw = (raw or "").strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        return raw[1:-1]
    return raw


def _inline(raw: str) -> Dict[str, str]:
    body = raw.strip()[1:-1] if raw.strip().startswith("{") else ""
    return {k: _tstr(v) for k, v in re.findall(
        r"([A-Za-z0-9_\-]+)\s*=\s*(\"(?:[^\"\\]|\\.)*\"|'[^']*'|\[[^\]]*\]|[^,}\s]+)", body)}


def cargo_deps(text: str) -> Dict[str, Dict[str, str]]:
    """Dependencies of a Cargo.toml (every dependency table, [workspace.dependencies]
    and [patch.*] too): name -> spec ({"version": ..} or the inline table)."""
    specs: Dict[str, Dict[str, str]] = {}
    for table, key, raw in toml_entries(text):
        if _DEP_TABLE.match(table) or table.startswith("patch."):
            dep, _, attr = key.partition(".")            # serde.workspace = true
            spec = specs.setdefault(dep, {})
            if attr:
                spec[attr] = _tstr(raw)
            elif raw.startswith("{"):
                spec.update(_inline(raw))
            else:
                spec["version"] = _tstr(raw)
            continue
        m = _DEP_SUBTABLE.match(table)
        if m:                                            # [dependencies.serde] path = "..."
            specs.setdefault(m.group(1), {})[key] = _tstr(raw)
    return specs


def _dep_kind(spec: Dict[str, str]) -> str:
    if spec.get("path"):
        return "path"
    if spec.get("git"):
        return "git"
    if spec.get("workspace") == "true":
        return "workspace"
    return "registry"


def cargo_lock(text: str) -> List[Tuple[str, str, str]]:
    """(name, version, source) of each [[package]] of a Cargo.lock; source "" is local."""
    out = []
    for block in re.split(r"^\[\[package\]\]\s*$", text, flags=re.M)[1:]:
        block = re.split(r"^\[", block, maxsplit=1, flags=re.M)[0]
        name = re.search(r"^name\s*=\s*\"([^\"]*)\"", block, re.M)
        ver = re.search(r"^version\s*=\s*\"([^\"]*)\"", block, re.M)
        src = re.search(r"^source\s*=\s*\"([^\"]*)\"", block, re.M)
        if name:
            out.append((name.group(1), ver.group(1) if ver else "", src.group(1) if src else ""))
    return out


def _cargo_opts(args: Sequence[str]) -> Tuple[Dict[str, str], List[str]]:
    opts: Dict[str, str] = {}
    configs: List[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            break
        name, eq, val = a.partition("=")
        if name in _CARGO_VALUE:
            value = val if eq else (args[i + 1] if i + 1 < len(args) else "")
            if name == "--config":
                configs.append(value)
            else:
                opts[name] = value
            i += 1 if eq else 2
            continue
        if a.startswith("-"):
            opts[a] = ""
        i += 1
    return opts, configs


def _cargo_config(ctx: _Ctx, cwd: str) -> Tuple[Dict[str, Tuple[str, str, str]], List[ScriptFile]]:
    """The project's .cargo/config.toml files from the project folder down to
    cwd, merged (the one nearer cwd wins): key -> (raw value, base folder, file)."""
    out: Dict[str, Tuple[str, str, str]] = {}
    read: List[ScriptFile] = []
    mod = _mod(cwd)
    chain: List[str] = []
    cur = mod.normpath(cwd)
    while inside(cur, ctx.root, allow_equal=True):
        chain.append(cur)
        up = mod.dirname(cur)
        if up == cur:
            break
        cur = up
    for folder in reversed(chain):
        for name in ("config", "config.toml"):
            p = mod.join(folder, ".cargo", name)
            if _entry(ctx.ws, p, ctx.root) != "file":
                continue
            f, why = ctx.config(p)
            if f is None:
                ctx.skip(_rel(p, ctx.root), why, incomplete=True)
                continue
            read.append(f)
            for k, v in toml_flat(f.content).items():
                out[k] = (v, folder, f.rel)
    return out, read


def _rust_net_hits(ctx: _Ctx, f: ScriptFile) -> None:
    m = _RUST_NETWORK.search(f.content)
    if m:
        hit = ("embedded_execution", f"in {f.rel}: network use in code that runs at build time: {m.group(0)[:80]}")
        if hit not in ctx.ev.build_gates:
            ctx.ev.build_gates.append(hit)


def _proc_macro_files(ctx: _Ctx, crate_dir: str, flat: Dict[str, str]) -> Tuple[List[ScriptFile], List[str]]:
    """The lib file of a proc-macro crate and the module files it declares
    (`mod x;`, one level): (files read, files not read)."""
    mod = _mod(crate_dir)
    lib = _join(crate_dir, _tstr(flat.get("lib.path", "")) or "src/lib.rs")
    got: List[ScriptFile] = []
    missing: List[str] = []
    f, why = _read(ctx.ws, lib, ctx.root)
    if f is None:
        missing.append(f"{_rel(lib, ctx.root)} ({why})")
        ctx.skip(_rel(lib, ctx.root), why, incomplete=True)
        return got, missing
    got.append(f)
    if "#[path" in f.content:
        missing.append(f"modules of {f.rel} named with #[path]")
        ctx.skip(f.rel, "#[path] module attribute; not followed", incomplete=True)
    base = _dirname(lib)
    for name in _RUST_MOD.findall(f.content):
        for cand in (mod.join(base, name + ".rs"), mod.join(base, name, "mod.rs")):
            if _entry(ctx.ws, cand, ctx.root) == "file":
                g, gwhy = _read(ctx.ws, cand, ctx.root)
                if g is None:
                    missing.append(f"{_rel(cand, ctx.root)} ({gwhy})")
                    ctx.skip(_rel(cand, ctx.root), gwhy, incomplete=True)
                else:
                    got.append(g)
                    if _RUST_MOD.search(g.content):
                        missing.append(f"modules declared inside {g.rel}")
                        ctx.skip(g.rel, "nested modules of a proc macro; not followed", incomplete=True)
                break
        else:
            missing.append(f"module {name} of {f.rel} (file not found)")
            ctx.skip(f"{f.rel} mod {name}", "module file not found", incomplete=True)
    return got, missing


def _cargo_build(ctx: _Ctx, args: List[str], cwd: str, label: str, env: Dict[str, str], manifest: str,
                 crate_dirs: Sequence[str] = (), build_files: Sequence[str] = ()) -> None:
    opts, cfg_args = _cargo_opts(args)
    head = f"checked by code: what {label} downloads and runs while it builds"
    offline = ""
    if "--frozen" in opts:
        offline = "--frozen in the command"
    elif "--offline" in opts:
        offline = "--offline in the command"
    elif env.get("CARGO_NET_OFFLINE", "").strip().lower() in ("true", "1"):
        offline = "CARGO_NET_OFFLINE=true in the command"
    elif any(re.sub(r"\s", "", c).lower() == "net.offline=true" for c in cfg_args):
        offline = "--config net.offline=true in the command"
    locked = "--frozen in the command" if "--frozen" in opts else ("--locked in the command" if "--locked" in opts else "")
    progs: List[str] = []
    for var, what in (("RUSTC_WRAPPER", "for every rustc run"), ("CARGO_BUILD_RUSTC_WRAPPER", "for every rustc run"),
                      ("RUSTC_WORKSPACE_WRAPPER", "for every rustc run on the project's crates")):
        if env.get(var):
            progs.append(_prog_fact(ctx, env[var], cwd, f"{var} in the command", what))
    extra = [f"--config {_show(c, 150)} in the command (not checked)." for c in cfg_args
             if re.sub(r"\s", "", c).lower() != "net.offline=true"]
    if env.get("RUSTFLAGS"):
        extra.append(f"RUSTFLAGS in the command: {_show(env['RUSTFLAGS'], 150)} (flags for rustc; not checked).")
    if ctx.ws is None or not manifest:
        known = [f"{offline}: cargo downloads nothing."] if offline else []
        if locked:
            known.append(f"{locked}: cargo does not change Cargo.lock.")
        what = ("Cargo.toml, Cargo.lock, .cargo/config.toml and the crates were not read (no file access)."
                if ctx.ws is None else "no Cargo.toml inside the project folder, so what cargo downloads was not checked.")
        ctx.ev.facts.append(head + ": " + what + " " + " ".join(known + [p for p in progs if p] + extra))
        return
    mdir = _dirname(manifest)
    cfg, cfg_files = _cargo_config(ctx, cwd)
    for key, (raw, base, rel) in sorted(cfg.items()):
        if key in ("build.rustc-wrapper", "build.rustc-workspace-wrapper", "build.rustc"):
            progs.append(_prog_fact(ctx, _tstr(raw), base, f"{rel} {key}", "for every rustc run"))
        elif re.match(r"^target\..+\.runner$", key):
            value = _tstr(raw) if not raw.startswith("[") else " ".join(re.findall(r"\"([^\"]*)\"", raw))
            progs.append(_prog_fact(ctx, value, base, f"{rel} {key}", "to start each test binary"))
        elif re.match(r"^target\..+\.linker$", key) or key == "build.rustflags" or re.match(r"^target\..+\.rustflags$", key):
            extra.append(f"{rel} {key} = {_show(raw, 120)} (not checked).")
    if not offline and _tstr(cfg.get("net.offline", ("", "", ""))[0]).lower() == "true":
        offline = f"{cfg['net.offline'][2]} net.offline = true"
    progs = [p for p in progs if p]
    # crates of the project: the root, workspace members, path dependencies inside the project
    flats: Dict[str, Dict[str, str]] = {}
    dirs = list(crate_dirs) or [mdir]
    deps: List[Tuple[str, str, Dict[str, str]]] = []     # (crate folder, name, spec)
    i = 0
    while i < len(dirs) and i < 30:
        d = dirs[i]
        i += 1
        man = manifest if d == mdir else _mod(d).join(d, "Cargo.toml")
        g, _ = ctx.config(man) if _entry(ctx.ws, man, ctx.root) == "file" else (None, "")
        if g is None:
            continue
        flat = toml_flat(g.content)
        flats[d] = flat
        for name, spec in cargo_deps(g.content).items():
            deps.append((d, name, spec))
            if _dep_kind(spec) == "path":
                full = _join(d, spec["path"])
                if inside(full, ctx.root, allow_equal=True) and full not in dirs:
                    dirs.append(full)
    path_out = sorted({f"{n} ({s['path']})" for d, n, s in deps if _dep_kind(s) == "path"
                       and not inside(_join(d, s["path"]), ctx.root, allow_equal=True)})
    git_decl = sorted({s["git"] for _, _, s in deps if _dep_kind(s) == "git"})
    reg_decl = sorted({n for _, n, s in deps if _dep_kind(s) == "registry"})
    # build scripts of path dependencies inside the project (the members' are read above)
    build_rels = list(build_files)
    for d in dirs:
        if d in crate_dirs or d not in flats:
            continue
        custom = _tstr(flats[d].get("package.build", ""))
        if custom == "false":
            continue
        b = _join(d, custom) if custom else _mod(d).join(d, "build.rs")
        if _entry(ctx.ws, b, ctx.root) == "file":
            bf, bwhy = _read(ctx.ws, b, ctx.root)
            if bf is None:
                ctx.skip(_rel(b, ctx.root), bwhy, incomplete=True)
                build_rels.append(f"{_rel(b, ctx.root)} (not read: {bwhy})")
            else:
                ctx.add_file(bf, d)
                build_rels.append(bf.rel)
    # proc macros of the project
    macros: List[str] = []
    macro_missing: List[str] = []
    macro_files: List[ScriptFile] = []
    for d in dirs:
        flat = flats.get(d, {})
        if _tstr(flat.get("lib.proc-macro", flat.get("lib.proc_macro", ""))).lower() != "true":
            continue
        name = _tstr(flat.get("package.name", "")) or _rel(d, ctx.root)
        got, missing = _proc_macro_files(ctx, d, flat)
        macros.append(f"{name} ({', '.join(x.rel for x in got) or 'not read'})")
        macro_missing += missing
        for x in got:
            ctx.add_file(x, d)
            macro_files.append(x)
    # network check of all build-time code of the project
    build_paths = {x.path for x in macro_files}
    for x in ctx.ev.files:
        if x.path in build_paths or x.rel in build_rels:
            _rust_net_hits(ctx, x)
    # Cargo.lock
    lock_path = _find_up(ctx, mdir, ("Cargo.lock",))
    lock = None
    pkgs: List[Tuple[str, str, str]] = []
    if lock_path:
        lock, why = ctx.config(lock_path)
        if lock is None:
            ctx.skip(_rel(lock_path, ctx.root), why, incomplete=True)
            return
        pkgs = cargo_lock(lock.content)
    reg = [p for p in pkgs if p[2].startswith(("registry+", "sparse+"))]
    git = [p for p in pkgs if p[2].startswith("git+")]
    # vendored sources / mirrors
    repl = _tstr(cfg.get("source.crates-io.replace-with", ("", "", ""))[0])
    vendored = mirror = ""
    vendor_rel = ""
    if repl:
        raw, base, rel = cfg.get(f"source.{repl}.directory", ("", "", ""))
        if raw:
            vdir = _join(base, _tstr(raw))
            if inside(vdir, ctx.root) and _entry(ctx.ws, vdir, ctx.root) == "dir":
                vendored, vendor_rel = vdir, _rel(vdir, ctx.root)
        for kind in ("registry", "local-registry"):
            raw2 = cfg.get(f"source.{repl}.{kind}", ("", "", ""))[0]
            if raw2:
                mirror = _tstr(raw2)
    git_vendored = {_tstr(v[0]) for k, v in cfg.items() if k.startswith("source.") and k.endswith(".git")
                    and _tstr(cfg.get(k[:-4] + ".replace-with", ("", "", ""))[0]) == repl} if vendored else set()
    git_open = [u for u in git_decl if u not in git_vendored]
    summary: List[str] = []
    summary.append(f"build script{'s' if len(build_rels) > 1 else ''} {_short(build_rels, 3)} (run at build time, "
                   f"content below)" if build_rels else "no build.rs")
    summary.append(f"proc macro crate{'s' if len(macros) > 1 else ''} of the project: {_short(macros, 3)} (run inside "
                   f"the compiler at build time, content below)" if macros else "no proc macro crate in the project")
    summary.append(f"{lock.rel} present" if lock is not None else "no Cargo.lock")
    # downloads
    n_ext = len(reg) + len(git)
    if offline:
        dl = f"{offline}: cargo downloads nothing; it stops with an error if a crate is not already in its cache."
        summary.append("downloads nothing (offline)")
    elif lock is not None and n_ext == 0 and not git_decl:
        dl = f"{lock.rel} lists no crate from a registry or git, so cargo downloads nothing."
        summary.append("downloads nothing (no crate from a registry or git)")
    elif lock is None and not reg_decl and not git_decl:
        dl = ("Cargo.lock does not exist, and Cargo.toml declares no dependency from a registry or git, so cargo "
              "downloads nothing.")
        summary.append("downloads nothing (no dependency from a registry or git)")
    elif vendored and not git_open:
        dl = (f"{cfg['source.crates-io.replace-with'][2]} replaces crates.io with the folder {vendor_rel}/ inside the "
              f"project folder ([source] replace-with), so cargo takes the crates from there and downloads nothing.")
        summary.append(f"dependencies vendored in {vendor_rel}/, so cargo downloads nothing")
    elif lock is None:
        dl = (f"Cargo.lock does not exist: cargo picks the newest versions that match Cargo.toml ("
              + ", ".join(x for x in (f"{len(reg_decl)} from " + (mirror or "crates.io") if reg_decl else "",
                                      f"{len(git_decl)} from git: {_short(git_decl, 2)}" if git_decl else "") if x)
              + ") and downloads them (not pinned by a lockfile).")
        summary.append("dependencies not pinned and not vendored, so cargo downloads them unless --offline")
    else:
        src = mirror or "crates.io"
        dl = (f"{lock.rel} pins the versions and checksums of {len(reg)} crate{'s' if len(reg) != 1 else ''} from {src}"
              + (f" and {len(git)} from git ({_short(sorted({p[2].split('#')[0][4:] for p in git}), 2)})" if git else "")
              + f". cargo downloads the ones not already in its cache (CARGO_HOME) unless --offline "
                f"is given.")
        summary.append(f"dependencies not vendored, so cargo may download {n_ext} crate{'s' if n_ext != 1 else ''} "
                       f"unless --offline")
    if locked:
        dl += f" {locked}: cargo does not change Cargo.lock (it stops if Cargo.lock is out of date)."
    elif lock is not None and not offline:
        dl += " Without --locked, cargo changes Cargo.lock only when Cargo.toml asks for a dependency it does not match."
    if path_out:
        dl += (f" Path dependencies outside the project folder: {_short(path_out, 3)}; their code, build scripts and "
               f"proc macros were not read.")
        summary.append("path dependencies outside the project (not read)")
    # dependency code that runs at build time
    if n_ext == 0 and not git_decl and not reg_decl:
        dep_run = "No crate from a registry or git, so no outside code runs while cargo builds."
    elif vendored and not git_open:
        with_code = []
        for name, version, source in reg[:VENDOR_CRATES_MAX]:
            for cand in (name, f"{name}-{version}"):
                cdir = _mod(vendored).join(vendored, cand)
                if _entry(ctx.ws, cdir, ctx.root) != "dir":
                    continue
                parts = []
                if _entry(ctx.ws, _mod(cdir).join(cdir, "build.rs"), ctx.root) == "file":
                    parts.append("build script")
                vf, _ = _read(ctx.ws, _mod(cdir).join(cdir, "Cargo.toml"), ctx.root)
                if vf is not None and _tstr(toml_flat(vf.content).get("lib.proc-macro", "")).lower() == "true":
                    parts.append("proc macro")
                if parts:
                    with_code.append(f"{cand} ({' and '.join(parts)})")
                break
        dep_run = (f"Vendored crates that run code while cargo builds: {_short(with_code)}; their code was not read."
                   if with_code else "No vendored crate has a build script or is a proc macro.")
        if with_code:
            summary.append("vendored crates with build-time code (not read)")
    else:
        dep_run = ("Crates from a registry or git can have their own build scripts and proc macros, which run while "
                   "cargo builds; their code is not in the project folder and was not read.")
        summary.append("build scripts and proc macros of the dependency crates (if any) not read")
    runs = []
    if build_rels:
        runs.append(f"Build scripts of the project, run by cargo before it compiles the crate: {_short(build_rels, 5)} "
                    f"(content below).")
    if macros:
        runs.append(f"Proc macro crates of the project, run inside the compiler while it compiles the crates that use "
                    f"them: {_short(macros, 5)} (content below)." + (f" Not read: {_short(macro_missing, 3)}."
                                                                   if macro_missing else ""))
    runs.append(dep_run)
    runs += progs
    if progs:
        summary.append("a wrapper or runner program (see below)")
    target = opts.get("--target-dir") or env.get("CARGO_TARGET_DIR") or _tstr(cfg.get("build.target-dir", ("", "", ""))[0])
    tdir = _join(cwd, target) if target else _mod(mdir).join(_dirname(lock_path) if lock_path else mdir, "target")
    written = (f"Build output goes to {_rel(tdir, ctx.root)}/ inside the project folder."
               if inside(tdir, ctx.root) else f"Build output goes to {tdir}, outside the project folder.")
    if lock is None:
        written += " cargo writes Cargo.lock in the project folder."
    text = [head + f" ({_rel(manifest, ctx.root)} {_sha(ctx.seen_configs[manifest]) if manifest in ctx.seen_configs else ''}"
            .rstrip() + "):",
            "  summary: " + "; ".join(summary) + ".",
            "  downloads: " + dl,
            "  runs while building: " + " ".join(runs),
            "  files written: " + written]
    if cfg_files:
        text.append(f"  cargo configuration read: {', '.join(x.rel for x in cfg_files)} (cargo also reads "
                    f"~/.cargo/config.toml, not read).")
    if extra:
        text.append("  also: " + " ".join(extra))
    ctx.ev.facts.append("\n".join(text))


# ---------- tox / nox ----------


def _tox(ctx: _Ctx, args: List[str], cwd: str, depth: int, label: str) -> None:
    envs: List[str] = []
    conf, i = "", 0
    rest = list(args)
    if rest[:1] and rest[0] in ("run", "r", "run-parallel", "p", "exec", "e"):
        rest = rest[1:]
    elif rest[:1] and not rest[0].startswith("-"):
        return                         # tox list, tox config, tox devenv ...: not a test run
    while i < len(rest):
        a = rest[i]
        if a == "--":
            break
        if a in _TOX_VALUE and i + 1 < len(rest):
            if a in ("-e", "--env"):
                envs.extend(x for x in rest[i + 1].split(",") if x)
            elif a in ("-c", "--conf"):
                conf = rest[i + 1]
            i += 2
            continue
        if a.startswith("-e") and len(a) > 2 and not a.startswith("--"):
            envs.extend(x for x in a[2:].lstrip("=").split(",") if x)
        i += 1
    ctx.runner("tox")
    head = (f"checked by code: {label} runs tox in {_where(cwd, ctx.root)}: for each environment it creates a Python "
            f"virtual environment, installs the listed deps and the project into it (with pip, from the network or a "
            f"cache), and runs the listed commands.")
    if ctx.ws is None:
        ctx.ev.facts.append(head + " The tox configuration was not read.")
        return
    path = _join(cwd, conf) if conf else _find_up(ctx, cwd, ("tox.ini",))
    body = ""
    if path:
        f, why = ctx.config(path)
        if f is None:
            ctx.skip(_rel(path, ctx.root), why, incomplete=True)
            return
        body = f.content
    else:
        for name in ("setup.cfg", "pyproject.toml"):
            p = _find_up(ctx, cwd, (name,))
            if not p:
                continue
            g, _ = ctx.config(p)
            if g is None:
                continue
            if name == "pyproject.toml":
                m = re.search(r"legacy_tox_ini\s*=\s*(?:\"\"\"|''')(.*?)(?:\"\"\"|''')", g.content, re.S)
                if m:
                    f, body = g, m.group(1)
                    break
            elif "[tox:tox]" in g.content:
                f, body = g, g.content.replace("[tox:tox]", "[tox]")
                break
        if not body:
            ctx.ev.facts.append(head + " No tox configuration (tox.ini, setup.cfg [tox:tox], pyproject.toml "
                                       "legacy_tox_ini) was found inside the project folder.")
            return
    parser = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True)
    try:
        parser.read_string(body)
    except configparser.Error:
        ctx.skip(f.rel, "tox configuration could not be parsed", incomplete=True)
        return
    if not envs:
        raw = parser.get("tox", "envlist", fallback="") or parser.get("tox", "env_list", fallback="")
        envs = [x.strip() for x in re.split(r"[\s,]+", raw or "") if x.strip()]
    sections: List[str] = ["testenv"] + [f"testenv:{e}" for e in envs if parser.has_section(f"testenv:{e}")]
    if any("{" in e for e in envs):
        sections += [s for s in parser.sections() if s.startswith("testenv:") and s not in sections]
    text = [head + f" From {f.rel} ({_sha(f)}), environments: {', '.join(envs) or '(default)'}:"]
    pending: List[Tuple[str, str, str]] = []
    for s in sections:
        if not parser.has_section(s):
            continue
        text.append(f"  [{s}]")
        for key in ("deps", "commands_pre", "commands", "commands_post", "allowlist_externals",
                    "whitelist_externals", "install_command", "change_dir", "changedir"):
            value = parser.get(s, key, fallback=None)
            if not value:
                continue
            items = [x.strip() for x in value.splitlines() if x.strip()]
            text.append(f"    {key}: " + " | ".join(x[:LINE_SHOW] for x in items)[:900])
            if key.startswith("commands") or key == "install_command":
                for line in items:
                    pending.append((f"{f.rel} [{s}] {key}", line.lstrip("-").strip(), f"[{s}] {key}"))
    ctx.ev.facts.append("\n".join(text))
    for where, line, who in pending:
        if ctx.add_line(where, line, cwd):
            _walk(ctx, line.replace("{posargs}", ""), cwd, depth + 1, who)
            _local_scripts(ctx, line, cwd, depth, where)


def _nox(ctx: _Ctx, args: List[str], cwd: str, label: str) -> None:
    sessions, nfile, i = [], "", 0
    while i < len(args):
        a = args[i]
        if a in ("-l", "--list", "--list-sessions", "--version", "-h", "--help"):
            return
        if a in _NOX_VALUE and i + 1 < len(args):
            if a in ("-s", "--session", "--sessions"):
                sessions.append(args[i + 1])
            elif a in ("-f", "--noxfile"):
                nfile = args[i + 1]
            i += 2
            continue
        i += 1
    ctx.runner("nox")
    head = (f"checked by code: {label} runs nox in {_where(cwd, ctx.root)}: it runs the session functions of the "
            f"noxfile{(' ' + ', '.join(sessions)) if sessions else ''}, which create virtual environments, install "
            f"packages and run commands.")
    if ctx.ws is None:
        ctx.ev.facts.append(head + " The noxfile was not read.")
        return
    path = _join(cwd, nfile or "noxfile.py")
    f, why = _read(ctx.ws, path, ctx.root)
    if f is None:
        ctx.skip(_rel(path, ctx.root), why, incomplete=True)
        return
    ctx.add_file(f, cwd)
    ctx.ev.facts.append(head + f" The noxfile runs as code (content below): {f.rel}.")


# ---------- entry point ----------


def derived_envelope(envelope: Envelope, line: ConfigLine) -> Envelope:
    """The envelope of `line` run as the command itself: same grant, user and
    project; cwd is the folder the line runs in; no trajectory (injection is
    judged on the real command)."""
    env = dataclasses.replace(envelope.environment, cwd=line.cwd or envelope.environment.cwd)
    return dataclasses.replace(envelope, action=ProposedAction(tool="bash", arguments={"command": line.line}),
                               environment=env, trajectory=Trajectory())


def _marker_passages(text: str, where: str, cap: int) -> str:
    parts: List[str] = []
    total = 0
    for marker in injection.INSTRUCTION_MARKERS:
        for m in marker.finditer(text):
            passage = " ".join(text[max(0, m.start() - injection._SNIPPET):m.end() + injection._SNIPPET].split())
            piece = f"[from {where}] ...{passage}..."[: max(0, cap - total)]
            if piece:
                parts.append(piece)
                total += len(piece)
            if total >= cap:
                return "\n".join(parts)
    return "\n".join(parts)


def collect(envelope: Envelope, workspace: Any, scripts: Sequence[ScriptFile] = (),
            build_facts: bool = False, path_env: Optional[str] = None,
            read_test_sources: bool = False) -> TestRunEvidence:
    """Find the test runs of the command (and of shell scripts F4 read) and
    what they run. Never raises. `scripts`: the F4 files (not repeated)."""
    command = envelope.action.arguments.get("command")
    env = envelope.environment
    root = env.project_root
    ctx = _Ctx(workspace, root, scripts, build=build_facts, path_env=path_env, read_test_sources=read_test_sources)
    if not isinstance(command, str) or not command.strip() or not root:
        return ctx.ev
    cwd = env.cwd or root
    try:
        _walk(ctx, command, cwd, 0, "")
        for s in scripts:
            if s.kind == "shell":
                _walk(ctx, s.content, s.run_cwd or cwd, 1, s.rel)
    except Exception as exc:
        ctx.skip("", f"error: {type(exc).__name__}")
    ev = ctx.ev
    if not ev.facts and not ev.files:
        return ev
    if ctx.incomplete:
        return ev                   # evidence only when everything that runs was read (the F4 rule)
    try:
        sections = list(ev.facts)
        bodies = []
        total = 0
        for f in ev.files:
            body, n = scriptsource.scrub(f.content)
            ev.redactions += n
            bodies.append((f, body))
            total += len(body)
        facts_text, n = scriptsource.scrub("\n".join(sections))
        ev.redactions += n
    except Exception:
        ev.scrub_failed = True
        return ev
    contexts = [_marker_passages(facts_text, "project configuration a test command runs", scriptsource.SOURCE_CONTEXT_CAP)]
    contexts += [scriptsource.marker_passages(f, text=body) for f, body in bodies]
    ev.injection = any(contexts)
    if ev.injection:
        ev.context_text = "\n".join(c for c in contexts if c)[: scriptsource.SOURCE_CONTEXT_CAP]
        return ev
    parts = [facts_text]
    if bodies and total <= SOURCE_CAP:
        for f, body in bodies:
            parts.append(f"checked by code: current content of {f.rel}, sha256 {f.sha256[:12]}, {f.size} bytes\n{body}")
    elif bodies:
        parts.append(f"checked by code: the code files named above hold {total} characters together, more than "
                     f"{SOURCE_CAP}; their content is not shown here.")
    ev.source_text = "\n\n".join(parts)
    return ev


def iter_files(ev: Optional[TestRunEvidence]) -> Iterable[ScriptFile]:
    return list(ev.files) if ev is not None else []
