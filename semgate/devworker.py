"""Offline development process tree, separate from the prepared HTTP sender.

The optional backend uses existing Linux bubblewrap/libseccomp, directly or
in an already-running WSL distribution. This file is also a stdlib-only -I
entry point. It never installs tools, starts a distribution, or falls back to
unconfined execution. Worker input is created by the trusted broker.
"""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from dataclasses import dataclass

if __package__:
    from . import proc
    from . import cachecleanup
    from . import readonlyscript
else:
    # The -I Linux bootstrap must not import the package (and its SDK) or
    # resolve project modules. Load only the adjacent trusted stdlib wrapper.
    import importlib.util
    _spec = importlib.util.spec_from_file_location("semgate_worker_proc", Path(__file__).with_name("proc.py"))
    proc = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(proc)
    _cache_spec = importlib.util.spec_from_file_location("semgate_worker_cachecleanup", Path(__file__).with_name("cachecleanup.py"))
    cachecleanup = importlib.util.module_from_spec(_cache_spec)
    sys.modules[_cache_spec.name] = cachecleanup
    _cache_spec.loader.exec_module(cachecleanup)
    _script_spec = importlib.util.spec_from_file_location("semgate_worker_readonlyscript", Path(__file__).with_name("readonlyscript.py"))
    readonlyscript = importlib.util.module_from_spec(_script_spec)
    sys.modules[_script_spec.name] = readonlyscript
    _script_spec.loader.exec_module(readonlyscript)

MAX_COMMAND = 4096
MAX_OUTPUT = 16384

# Names the worker masks or mounts read-only, at the project root only (see the
# mount plan in execute()). The same name deeper in the project is an ordinary
# writable directory in the guest, so its files stay inside the audited view.
PROTECTED_PROJECT_NAMES = frozenset({".semgate", ".codex", ".agents", ".git", ".venv"})

# A Windows name surrogate (directory junction) is reported by lstat as a
# directory with a reparse tag. Following it would count the target's names as
# if they were inside the project, and could count one name twice; the guest
# sees a dangling name instead.
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _is_name_surrogate(info) -> bool:
    """True for a directory that stands for another directory."""
    attributes = getattr(info, "st_file_attributes", 0)
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


class WriteConfinementError(RuntimeError):
    """The writable project view cannot guarantee write confinement.

    Raised by the trusted host before any effectful command runs. It is a
    refusal, not a setup failure: no unconstrained fallback is selected.
    """

    reason_code = "development_alias_audit_failed"

    def __init__(self, audit: dict, detail: str) -> None:
        super().__init__(detail)
        self.audit = audit

    def summary(self) -> str:
        return describe_audit(self.audit)


class AliasAuditError(WriteConfinementError):
    """A writable project file also has a name outside the workspace."""

    reason_code = "development_alias_audit_failed"

    def __init__(self, audit: dict) -> None:
        super().__init__(audit, "offline worker refused the command: the writable project view shares a file "
                               "with a name outside the workspace")

    def summary(self) -> str:
        offenders = self.audit.get("offenders") or []
        paths = ", ".join(sorted({path for item in offenders for path in item.get("paths", [])}))
        return f"{len(offenders)} project file(s) also have a name outside the writable workspace: {paths}"


class IncompleteAuditError(WriteConfinementError):
    """The audit could not complete, so write confinement is not established."""

    reason_code = "development_alias_audit_incomplete"

    def __init__(self, audit: dict) -> None:
        super().__init__(audit, "offline worker refused the command: the write-confinement audit could not "
                               "complete, so confinement is not established")

    def summary(self) -> str:
        return (f"{self.audit.get('unverifiable', 0)} entr(y/ies) in the writable project view could not be "
                f"checked ({self.audit.get('checked', 0)} file(s) checked)")


def audit_write_confinement(project: Path) -> dict:
    """Fail closed when a writable project file shares its file with a name outside it.

    A hard link is a second directory entry for one file, so it crosses the
    mount boundary: an in-place write through the inside name changes the
    outside file even though the command never names an outside path. The
    writable view is the project without the project-root names the guest
    cannot write (hidden metadata trees, read-only metadata and environment
    mounts). Every file is counted once per name inside that view; a file whose
    link count exceeds the number of names inside the view has a name outside
    it. A name surrogate (Windows junction) is not descended into: its target
    is not part of the project view, and counting it would count one name
    twice.

    An entry that cannot be listed or stat'ed leaves the audit incomplete:
    listing a directory and writing inside it are different permissions, so an
    unreadable name can still be writable in the guest. Callers must refuse an
    incomplete audit as well as a proven alias.

    The audit is a snapshot taken immediately before the command starts. The
    sandboxed agent cannot add an escaping name itself: link() to another
    filesystem or mount fails, and a link inside the project keeps both names
    inside the view. Only an outside process that creates a hard link into the
    project during the command could reintroduce the condition. The alias,
    junction and unreadable-directory cases above need no such race.
    """
    counts: dict[tuple[int, int], int] = {}
    links: dict[tuple[int, int], int] = {}
    names: dict[tuple[int, int], list[str]] = {}
    checked = 0
    unverifiable = 0
    surrogates: list[str] = []
    stack = [(project, True)]
    while stack:
        current, is_root = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            unverifiable += 1
            continue
        for entry in entries:
            if is_root and entry.name in PROTECTED_PROJECT_NAMES:
                # The mount plan masks these project-root names only.
                continue
            try:
                # os.lstat, not the cached directory entry: on Windows the
                # directory entry carries no file index or link count.
                info = os.lstat(entry.path)
            except OSError:
                unverifiable += 1
                continue
            if stat.S_ISDIR(info.st_mode):
                if _is_name_surrogate(info):
                    surrogates.append(os.path.relpath(entry.path, project))
                    continue
                stack.append((entry.path, False))
            elif stat.S_ISREG(info.st_mode):
                key = (info.st_dev, info.st_ino)
                checked += 1
                counts[key] = counts.get(key, 0) + 1
                links[key] = info.st_nlink
                names.setdefault(key, []).append(os.path.relpath(entry.path, project))
    offenders = []
    for key, number in counts.items():
        if number < links[key]:
            offenders.append({"paths": sorted(names[key])[:4], "names_in_view": number,
                              "link_count": links[key]})
    return {"checked": checked, "inodes": len(counts), "unverifiable": unverifiable,
            "offenders": offenders[:8], "surrogates": sorted(surrogates)[:8]}


def validate_write(arguments: dict) -> dict:
    """A small literal UTF-8 replacement, never an executable program or host path."""
    if not isinstance(arguments, dict) or set(arguments) != {"path", "content"}:
        raise ValueError("invalid local write fields")
    path, content = arguments["path"], arguments["content"]
    if (not isinstance(path, str) or not 1 <= len(path) <= 512 or any(c in path for c in "\\:\0")
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or any(part.casefold() in {".semgate", ".codex", ".agents", ".git", ".venv"} for part in path.split("/"))):
        raise ValueError("local write requires an unprotected relative path")
    if not isinstance(content, str) or "\0" in content or len(content.encode("utf-8")) > 4096:
        raise ValueError("local write content limit")
    return dict(arguments)


# Executed by the system Python with -I inside the SAME offline namespace as
# development commands. Arguments are data; no project imports or shell parsing.
# Directory descriptors and no-follow opens prevent symlink traversal. Replacing
# the directory entry also avoids mutating an existing hard-linked inode.
_WRITE_PROGRAM = """
import os,sys,stat,secrets,hashlib,json
path,content=sys.argv[1:]
data=content.encode('utf-8')
directory=os.open('/workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
temporary=None
try:
 for part in path.split('/')[:-1]:
  child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
  os.close(directory)
  directory=child
 name=path.split('/')[-1]
 try:
  existing=os.stat(name,dir_fd=directory,follow_symlinks=False)
  if not stat.S_ISREG(existing.st_mode): raise ValueError('non-regular target')
 except FileNotFoundError: pass
 temporary='.semgate-write-'+secrets.token_hex(16)
 fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory)
 with os.fdopen(fd,'wb') as stream:
  stream.write(data)
  stream.flush()
  os.fsync(stream.fileno())
 os.replace(temporary,name,src_dir_fd=directory,dst_dir_fd=directory)
 temporary=None
 print(json.dumps({'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}))
finally:
 if temporary is not None: os.unlink(temporary,dir_fd=directory)
 os.close(directory)
"""


# What the worker enforces for every ordinary command, in the judge's words.
# The per-project audit result belongs in the refusal receipt, not in the
# capability facts: the judge rules on intent, the host enforces confinement.
# Naming a project's alias in every judgment would deny unrelated work.
WRITE_CONFINEMENT_FACT = (
    "The worker verifies before execution that no file in the writable project view also has a name outside this "
    "workspace, and refuses the command when it finds one.")


def describe_audit(audit: dict) -> str:
    """The audited project state, for the operator-facing refusal."""
    offenders = audit.get("offenders") or []
    checked = int(audit.get("checked", 0))
    paths = ", ".join(sorted({path for item in offenders for path in item.get("paths", [])}))
    return f"audit checked {checked} files; {len(offenders)} file(s) also have a name outside the workspace: {paths}"


@dataclass(frozen=True)
class VerifiedOfflineFacts:
    launcher_version: str
    launcher_sha256: str
    cache_cleanup_command: str = ""
    script_snapshot: readonlyscript.ScriptSnapshot | None = None
    confinement: str = ""

    def render(self) -> str:
        if self.script_snapshot is not None:
            return (f"Verified by the trusted broker and successful offline inspection (bubblewrap {self.launcher_version}, "
                f"sha256 {self.launcher_sha256}): this invocation runs the exact inspected immutable Python source "
                f"snapshot {self.script_snapshot.sha256}. System Python runs with -I; project modules and user site packages "
                "are absent from its import path. The entire project is READ-ONLY; only guest temporary files are writable. "
                "The existing new network, mount and PID namespaces and socket-family filter apply to this process and children. "
                "No host TCP/UDP, Unix/VSOCK sockets, host home, broker/provider credentials or operator state are exposed. "
                "HTTP clients can attempt connections inside their private network namespace, but cannot upload to the host "
                "or Internet. This invocation has no persistent write capability. Source still needs intent and effect judgment; "
                "other credential, destructive and dynamic-execution guards still apply. External sends still require "
                "PreparedSender and current task consent. Setup failure never executes the source elsewhere.")
        audit = f" {self.confinement}" if self.confinement else ""
        return ("Verified by the trusted broker: a successful preflight used this command's offline worker profile "
                f"(bubblewrap {self.launcher_version}, sha256 {self.launcher_sha256}). "
                "The command and its children will execute only inside a new Linux network, mount and PID namespace, "
                "with no host network access, no host Unix/VSOCK sockets, no inherited broker/provider credentials or host home. "
                "Persistent writes are limited to this task's project workspace; protected operator metadata is hidden, "
                "git metadata and the host virtual environment are read-only. Temporary sandbox files are writable. "
                "Scripts and build/test tools execute inside that same boundary, including child processes. "
                "They can still modify or delete project files: assess those effects and task fit. "
                f"This fact is not permission to upload; all external sends require PreparedSender and current consent.{audit}"
                "The worker recreates and checks the same boundary before executing the requested command; setup failure never runs it on the host.")


class OfflineWorker:
    def __init__(self, settings: dict) -> None:
        if (not isinstance(settings, dict) or set(settings) - {"backend", "distribution", "tools", "timeout_s", "bubblewrap", "bubblewrap_sha256"}
                or settings.get("backend") not in {"bubblewrap", "wsl-bubblewrap"}):
            raise ValueError("invalid development worker configuration")
        self.settings = dict(settings)
        self.keeper = None
        timeout = settings.get("timeout_s", 300)
        if type(timeout) is not int or not 1 <= timeout <= 600:
            raise ValueError("invalid development deadline")
        self.timeout = timeout
        launcher = settings.get("bubblewrap", "/usr/bin/bwrap")
        if not isinstance(launcher, str) or not launcher.startswith("/") or "\0" in launcher:
            raise ValueError("invalid operator-owned bubblewrap path")
        digest = settings.get("bubblewrap_sha256")
        if digest is not None and (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("invalid bubblewrap digest")
        tools = settings.get("tools", {})
        if (not isinstance(tools, dict) or len(tools) > 16 or any(
                not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", name) or not isinstance(path, str)
                or not path.startswith("/") for name, path in tools.items())):
            raise ValueError("invalid operator-owned development tools")
        if settings["backend"] == "wsl-bubblewrap" and (os.name != "nt" or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", settings.get("distribution", ""))):
            raise ValueError("invalid running WSL distribution")
        if settings["backend"] == "bubblewrap" and sys.platform != "linux":
            raise ValueError("bubblewrap requires Linux")

    def verify(self, project: str, *, protected: tuple[str, ...] = ()) -> VerifiedOfflineFacts:
        # Fixed code-owned probe; it cannot execute agent instructions before judgment.
        receipt = self.run(project, "/usr/bin/true", protected=protected, check_confinement=False)
        version, digest = receipt.get("launcher_version"), receipt.get("launcher_sha256")
        if (receipt.get("exit_code") != 0 or receipt.get("timed_out") is not False
                or receipt.get("boundary") != "bubblewrap-offline/1"
                or not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+", version)
                or tuple(map(int, version.split("."))) < (0, 12, 0)
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or self.settings.get("bubblewrap_sha256") not in (None, digest)):
            raise RuntimeError("offline worker preflight failed")
        return VerifiedOfflineFacts(version, digest, confinement=WRITE_CONFINEMENT_FACT)

    def run(self, project: str, command: str, *, protected: tuple[str, ...] = (),
            expected_facts: VerifiedOfflineFacts | None = None,
            check_confinement: bool = True) -> dict:
        if not isinstance(command, str) or not command.strip() or len(command) > MAX_COMMAND or "\0" in command:
            raise ValueError("invalid development command")
        if expected_facts is not None and expected_facts.script_snapshot is not None:
            snapshot = expected_facts.script_snapshot
            if (snapshot.command != command or expected_facts.cache_cleanup_command
                    or not readonlyscript.network_probe_eligible(snapshot.source)):
                raise ValueError("isolated script facts do not match the command")
            return self._execute(project, {"script_snapshot": snapshot.payload()}, protected=protected, expected_facts=expected_facts)
        plan = cachecleanup.parse(command)
        if plan is not None:
            if expected_facts is None or expected_facts.cache_cleanup_command != command:
                raise ValueError("cache cleanup requires matching verified operation facts")
            result = self._execute(project, {"cache_cleanup": command}, protected=protected, expected_facts=expected_facts)
            if result["exit_code"] == 0:
                result.update(json.loads(result["stdout"]))
                if plan.status:
                    status = self._execute(project, {"command": "git status --short"}, protected=protected,
                                           expected_facts=expected_facts)
                    result = {**status, "cache_cleanup": result["cache_cleanup"],
                              "stdout": result["stdout"] + status["stdout"]}
            return result
        if expected_facts is not None and expected_facts.cache_cleanup_command:
            raise ValueError("cache cleanup facts cannot authorize a different command")
        return self._execute(project, {"command": command}, protected=protected, expected_facts=expected_facts,
                             check_confinement=check_confinement)

    def inspect_script(self, project: str, command: str, *, protected: tuple[str, ...],
                       expected_facts: VerifiedOfflineFacts) -> readonlyscript.ScriptSnapshot | None:
        path = readonlyscript.invocation(command)
        if path is None:
            return None
        receipt = self._execute(project, {"inspect_script": path}, protected=protected, expected_facts=expected_facts)
        if receipt["exit_code"] != 0 or receipt["timed_out"] or receipt["output_truncated"]:
            return None  # no relaxation; ordinary script-source guards still apply
        import base64, hashlib
        data = base64.b64decode(json.loads(receipt["stdout"])["source_base64"], validate=True)
        return readonlyscript.ScriptSnapshot(command, path, data.decode("utf-8"), hashlib.sha256(data).hexdigest())

    def write(self, project: str, arguments: dict, *, protected: tuple[str, ...] = (),
              expected_facts: VerifiedOfflineFacts | None = None) -> dict:
        return self._execute(project, {"write": validate_write(arguments)}, protected=protected, expected_facts=expected_facts)

    def _execute(self, project: str, operation: dict, *, protected: tuple[str, ...],
                 expected_facts: VerifiedOfflineFacts | None,
                 check_confinement: bool = True) -> dict:
        project_path = Path(project).resolve()
        worker_path = Path(__file__).resolve()
        if worker_path.is_relative_to(project_path):
            raise ValueError("the trusted Semgate installation must be outside the writable project")
        if "command" in operation and check_confinement:
            # An ordinary command may write in place. Refuse before execution
            # when the writable project view shares a file with a name outside
            # the workspace (a hard link crosses the mount boundary), and when
            # the audit could not complete: an unchecked name may still be
            # writable in the guest.
            audit = audit_write_confinement(project_path)
            if audit["offenders"]:
                raise AliasAuditError(audit)
            if audit["unverifiable"]:
                raise IncompleteAuditError(audit)
        if self.settings["backend"] == "wsl-bubblewrap":
            launcher = str(Path(os.environ["SystemRoot"]) / "System32/wsl.exe")
            running = proc.run([launcher, "--list", "--running", "--quiet"], timeout=10,
                               capture_output=True, check=True).stdout
            names = running.decode("utf-16-le" if b"\0" in running else "utf-8").split()
            distro = self.settings["distribution"]
            if distro not in names:
                raise ValueError("configured distribution is not already running")
            prefix = [launcher, "--distribution", distro, "--exec"]
            if self.keeper is None or self.keeper.poll() is not None:
                # A pipe kept open by this broker prevents WSL idle shutdown
                # between jobs. Closing it stops only this owned supervisor.
                self.keeper = proc.popen(prefix + ["/usr/bin/python3", "-I", "-c",
                    "import sys; sys.stdin.buffer.read()"], stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            def linux_path(path):
                return proc.run(prefix + ["/usr/bin/wslpath", "-u", str(path)], timeout=10,
                                text=True, capture_output=True, check=True).stdout.strip()
            project_name, entry = linux_path(project_path), linux_path(worker_path)
            argv = prefix + ["/usr/bin/python3", "-I", entry]
        else:
            project_name = str(project_path)
            argv = [sys.executable, "-I", str(worker_path)]
        hidden = []
        for name in protected:
            path = Path(name).resolve()
            if path.is_relative_to(project_path):
                hidden.append(path.relative_to(project_path).as_posix())
        payload = {"project": project_name, **operation, "timeout_s": self.timeout,
                   "tools": self.settings.get("tools", {}), "protected": hidden,
                   "bubblewrap": self.settings.get("bubblewrap", "/usr/bin/bwrap"),
                   "bubblewrap_sha256": (expected_facts.launcher_sha256 if expected_facts is not None
                                         else self.settings.get("bubblewrap_sha256"))}
        # Only the trusted bootstrap sees the host environment. bubblewrap
        # clears the guest environment and exposes no home or host /run.
        result = proc.run(argv, input=json.dumps(payload).encode(), capture_output=True, timeout=self.timeout + 20)
        if result.returncode != 0 or len(result.stdout) > 262144:
            raise RuntimeError("offline worker failed")
        value = json.loads(result.stdout)
        if not isinstance(value, dict) or value.get("boundary") != "bubblewrap-offline/1":
            raise RuntimeError("offline worker receipt missing")
        return value

    def close(self) -> None:
        if self.keeper is not None:
            self.keeper.stdin.close()
            try:
                self.keeper.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.keeper.terminate()
                self.keeper.wait(timeout=5)
            self.keeper = None


def _filter_file():
    """Use the system libseccomp compiler; do not hand-code architecture BPF.

    A network namespace handles TCP/UDP/DNS, including children. Other socket
    families could expose host services (Unix paths, VSOCK, Bluetooth).
    Anonymous Unix stream/seqpacket pairs remain usable for child-process IPC.
    """
    import ctypes as c
    import tempfile
    class Compare(c.Structure):
        _fields_ = [("arg", c.c_uint), ("op", c.c_int), ("a", c.c_uint64), ("b", c.c_uint64)]
    lib = c.CDLL("libseccomp.so.2")
    lib.seccomp_init.argtypes, lib.seccomp_init.restype = [c.c_uint32], c.c_void_p
    lib.seccomp_release.argtypes = [c.c_void_p]
    lib.seccomp_syscall_resolve_name.argtypes, lib.seccomp_syscall_resolve_name.restype = [c.c_char_p], c.c_int
    lib.seccomp_rule_add_array.argtypes = [c.c_void_p, c.c_uint32, c.c_int, c.c_uint, c.POINTER(Compare)]
    lib.seccomp_export_bpf.argtypes = [c.c_void_p, c.c_int]
    context = lib.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not context:
        raise RuntimeError("seccomp initialization failed")
    stream = tempfile.TemporaryFile()
    try:
        def deny(name, comparisons=()):
            number = lib.seccomp_syscall_resolve_name(name)
            if number < 0:
                raise RuntimeError("required seccomp syscall is unknown")
            args = (Compare * len(comparisons))(*comparisons) if comparisons else None
            if lib.seccomp_rule_add_array(context, 0x00050001, number, len(comparisons), args) != 0:
                raise RuntimeError("seccomp rule failed")
        # SCMP_CMP_EQ=4, NE=1, GE=5, MASKED_EQ=7. Only Internet socket
        # families are usable, within the new network namespace. Deny future
        # families too, rather than assuming that they are namespaced.
        for family in range(46):
            if family not in (2, 10):
                deny(b"socket", (Compare(0, 4, family, 0),))
        deny(b"socket", (Compare(0, 5, 46, 0),))
        deny(b"socketpair", (Compare(0, 1, 1, 0),))
        for kind in range(16):
            if kind not in (1, 5):  # STREAM/SEQPACKET: connected pairs cannot reconnect to host paths
                deny(b"socketpair", (Compare(1, 7, 15, kind),))
        for name in (b"io_uring_setup", b"io_uring_enter", b"io_uring_register"):
            deny(name)
        if lib.seccomp_export_bpf(context, stream.fileno()) != 0:
            raise RuntimeError("seccomp export failed")
        stream.seek(0)
        return stream
    except BaseException:
        stream.close()
        raise
    finally:
        lib.seccomp_release(context)


def execute(payload: dict) -> dict:
    import signal
    import threading
    project = Path(payload["project"]).resolve(strict=True)
    if not project.is_dir() or project == Path("/"):
        raise ValueError("invalid worker project")
    # DrvFS case aliases can bypass a mount covering .semgate or .git. Test
    # the actual project directory, not a child that may inherit other flags.
    import tempfile
    fd, name = tempfile.mkstemp(prefix=".semgate-FsProbe-", dir=project)
    os.close(fd)
    probe = Path(name)
    try:
        if (project / probe.name.swapcase()).exists():
            raise ValueError("offline development requires a case-sensitive project directory")
    finally:
        probe.unlink()
    launcher, version, digest = _launcher(payload, project)
    cleanup = "cache_cleanup" in payload
    snapshot = readonlyscript.ScriptSnapshot.from_payload(payload["script_snapshot"]) if "script_snapshot" in payload else None
    inspecting = "inspect_script" in payload
    if snapshot is not None or inspecting:
        if any(k in payload for k in ("command", "write", "cache_cleanup")) or snapshot is not None and inspecting:
            raise ValueError("ambiguous isolated script operation")
        if inspecting and readonlyscript.invocation("python3 " + str(payload["inspect_script"])) != payload["inspect_script"]:
            raise ValueError("invalid isolated source path")
    read_only = snapshot is not None or inspecting
    if cleanup:
        if cachecleanup.parse(payload["cache_cleanup"]) is None or "command" in payload or "write" in payload:
            raise ValueError("invalid cache cleanup operation")
    argv = [str(launcher), "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL"]
    for name in ("usr", "lib", "lib64", "bin", "sbin"):
        path = Path("/") / name
        if path.exists():
            argv += ["--ro-bind", str(path), str(path)]
    for name in ("/etc/hosts", "/etc/nsswitch.conf", "/etc/resolv.conf", "/etc/localtime", "/etc/ssl"):
        if Path(name).exists():
            argv += ["--ro-bind", name, name]
    argv += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/tools",
             "--ro-bind" if read_only else "--bind", str(project), "/workspace"]
    # A mount point cannot be renamed out of the way from inside the guest.
    for name in (".semgate", ".codex", ".agents"):
        # Only the fixed -I archiver needs its recovery store. No shell, Git,
        # project imports or other agent code runs in this profile. A trailing
        # git status runs in a separate ordinary, metadata-hidden namespace.
        if cleanup and name == ".semgate":
            continue
        if (project / name).exists():
            argv += ["--tmpfs", "/workspace/" + name, "--remount-ro", "/workspace/" + name]
    if (project / ".git").exists():
        argv += ["--ro-bind", str(project / ".git"), "/workspace/.git"]
    if (project / ".venv").exists():
        argv += ["--ro-bind", str(project / ".venv"), "/workspace/.venv"]
    for relative in payload["protected"]:
        path = Path(relative)
        if path.parts[0] in {".semgate", ".codex", ".agents", ".git"}:
            continue
        source = project / path
        if source.is_file():
            argv += ["--ro-bind", "/dev/null", "/workspace/" + relative]
        elif source.exists():
            raise ValueError("protected operator paths must be files")
    for name, source in payload["tools"].items():
        tool = Path(source).resolve(strict=True)
        if not tool.is_file() or tool.is_relative_to(project):
            raise ValueError("development tools must be operator-owned files outside the project")
        argv += ["--ro-bind", str(tool), "/tools/" + name]
    argv += ["--clearenv", "--setenv", "PATH", "/tools:/usr/bin:/bin", "--setenv", "HOME", "/tmp",
             "--setenv", "LANG", "C.UTF-8", "--setenv", "UV_PYTHON_DOWNLOADS", "never",
             "--setenv", "UV_PROJECT_ENVIRONMENT", "/workspace/.venv-linux",
             "--setenv", "UV_PYTHON_PREFERENCE", "only-system", "--setenv", "GIT_CONFIG_NOSYSTEM", "1",
             "--chdir", "/workspace"]
    from contextlib import ExitStack
    with _filter_file() as filter_file, ExitStack() as resources:
        inherited = [filter_file.fileno()]
        if snapshot is not None:
            import fcntl
            fd = os.memfd_create("semgate-reviewed-source", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            resources.callback(os.close, fd)
            data = snapshot.source.encode("utf-8")
            with os.fdopen(os.dup(fd), "wb") as stream:
                stream.write(data); stream.flush()
            os.lseek(fd, 0, os.SEEK_SET)
            fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            argv += ["--ro-bind-data", str(fd), "/semgate-reviewed.py"]
            inherited.append(fd)
            guest = ["/usr/bin/python3", "-I", "-B", "/semgate-reviewed.py"]
        elif inspecting:
            guest = ["/usr/bin/python3", "-I", "-c", readonlyscript.INSPECT, payload["inspect_script"]]
        elif cleanup:
            guest = ["/usr/bin/python3", "-I", "-c", cachecleanup.PROGRAM]
        elif "write" in payload:
            operation = validate_write(payload["write"])
            guest = ["/usr/bin/python3", "-I", "-c", _WRITE_PROGRAM, operation["path"], operation["content"]]
        else:
            guest = ["/bin/sh", "-c", payload["command"]]
        argv += ["--seccomp", str(filter_file.fileno()), "--", *guest]
        process = proc.popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   pass_fds=tuple(inherited), start_new_session=True)
        streams, truncated = [bytearray(), bytearray()], [False, False]
        def drain(pipe, index):
            with pipe:
                while chunk := pipe.read(4096):
                    room = MAX_OUTPUT - len(streams[index])
                    streams[index].extend(chunk[:room])
                    truncated[index] |= len(chunk) > room
        readers = [threading.Thread(target=drain, args=(pipe, i), daemon=True)
                   for i, pipe in enumerate((process.stdout, process.stderr))]
        for reader in readers:
            reader.start()
        expired = False
        try:
            process.wait(timeout=payload["timeout_s"])
        except subprocess.TimeoutExpired:
            expired = True
        finally:
            # Includes descendants and detached jobs inside the PID namespace.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            for reader in readers:
                reader.join(3)
        if any(reader.is_alive() for reader in readers):
            raise RuntimeError("worker pipes did not close")
        return {"boundary": "bubblewrap-offline/1", "exit_code": 124 if expired else process.returncode,
                **({"script_snapshot": {"path": snapshot.path, "sha256": snapshot.sha256,
                    "profile": "isolated-python-readonly/1"}} if snapshot is not None else {}),
                "launcher_version": version, "launcher_sha256": digest,
                "stdout": bytes(streams[0]).decode("utf-8", errors="replace"),
                "stderr": bytes(streams[1]).decode("utf-8", errors="replace"),
                "timed_out": expired, "output_truncated": any(truncated)}


def _launcher(payload: dict, project: Path) -> tuple[Path, str, str]:
    import hashlib
    launcher = Path(payload.get("bubblewrap", "/usr/bin/bwrap")).resolve(strict=True)
    if not launcher.is_file() or launcher.is_relative_to(project) or launcher.stat().st_mode & 0o6000:
        raise ValueError("bubblewrap must be a non-setuid operator-owned executable outside the project")
    digest = hashlib.sha256(launcher.read_bytes()).hexdigest()
    if payload.get("bubblewrap_sha256") not in (None, digest):
        raise ValueError("bubblewrap digest mismatch")
    text = proc.run([str(launcher), "--version"], check=True, capture_output=True, text=True, timeout=5).stdout.strip()
    match = re.fullmatch(r"bubblewrap (\d+)\.(\d+)\.(\d+)", text)
    if match is None or tuple(map(int, match.groups())) < (0, 12, 0):
        # CVE-2026-87766: sandbox setup can traverse attacker-controlled
        # symlinks. A working network namespace alone does not test this.
        raise ValueError("bubblewrap 0.12.0 or newer is required")
    return launcher, ".".join(match.groups()), digest


if __name__ == "__main__":
    try:
        raw = sys.stdin.buffer.read(32769)
        if len(raw) > 32768 or sys.platform != "linux":
            raise ValueError("invalid worker input")
        print(json.dumps(execute(json.loads(raw))))
    except Exception:
        print(json.dumps({"error": "offline_worker_unavailable"}))
        raise SystemExit(2)
