"""Read-only Git metadata projection for conventional linked worktrees.

The trusted broker resolves and checks host paths. The Linux bootstrap maps
only repository metadata, with guest-valid pointer files; it never repairs the
operator's worktree or exposes the main checkout.
"""
import hashlib
from pathlib import Path, PurePosixPath
import stat
import tempfile

GUEST_COMMON = "/semgate-git"
MAX_POINTER = 8192
MAX_CONFIG = 262144


def _read(path: Path, limit: int) -> bytes:
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("Git metadata pointer/configuration must be a regular file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Git metadata pointer/configuration exceeds its bound")
    return data


def _path_file(path: Path, prefix: str = "") -> Path:
    text = _read(path, MAX_POINTER).decode("utf-8").strip()
    if not text.startswith(prefix):
        raise ValueError("invalid Git metadata pointer")
    text = text[len(prefix):]
    if not text or any(c in text for c in "\r\n\0"):
        raise ValueError("invalid Git metadata pointer")
    return (path.parent / text).resolve(strict=True)


def layout(project: Path, protected: tuple[str, ...] = ()) -> dict | None:
    entry = project / ".git"
    try:
        info = entry.lstat()
    except FileNotFoundError:
        return None
    if stat.S_ISDIR(info.st_mode):
        return None
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Git metadata root must not be a link or special endpoint")
    admin = _path_file(entry, "gitdir: ")
    common = _path_file(admin / "commondir")
    relative = admin.relative_to(common)
    if (len(relative.parts) != 2 or relative.parts[0] != "worktrees"
            or any(ord(c) < 32 or ord(c) == 127 or c == "\\" for c in relative.as_posix())):
        raise ValueError("unsupported external Git metadata layout")
    if _path_file(admin / "gitdir") != entry.resolve(strict=True):
        raise ValueError("Git worktree metadata does not point back to this project")
    if (common.is_relative_to(project) or not stat.S_ISDIR((common / "objects").lstat().st_mode)
            or (common / "objects").resolve() != common / "objects"):
        raise ValueError("shared Git metadata must be outside the writable project")
    _read(common / "config", MAX_CONFIG)
    _read(admin / "HEAD", MAX_POINTER)
    alternates = common / "objects" / "info" / "alternates"
    if alternates.exists() and _read(alternates, MAX_CONFIG).strip():
        raise ValueError("alternate Git object stores are not exposed by the worker")
    for name in protected:
        path = Path(name).expanduser().absolute()
        if path.is_relative_to(common) or path.resolve().is_relative_to(common):
            raise ValueError("operator authority must not be exposed through shared Git metadata")
    return {"common": str(common), "relative": relative.as_posix(),
            "pointer_sha256": hashlib.sha256(_read(entry, MAX_POINTER)).hexdigest()}


def validate(project: Path, value: dict) -> dict:
    if not isinstance(value, dict) or set(value) != {"common", "relative", "pointer_sha256"}:
        raise ValueError("invalid Git metadata projection")
    if not all(isinstance(v, str) for v in value.values()):
        raise ValueError("invalid Git metadata projection")
    relative = PurePosixPath(value["relative"])
    if (relative.is_absolute() or len(relative.parts) != 2 or relative.parts[0] != "worktrees"
            or any(p in {"", ".", ".."} for p in relative.parts)
            or any(ord(c) < 32 or ord(c) == 127 or c == "\\" for c in value["relative"])):
        raise ValueError("invalid Git worktree metadata name")
    common = Path(value["common"]).resolve(strict=True)
    admin = common.joinpath(*relative.parts)
    if (common.is_relative_to(project) or not admin.is_dir() or admin.resolve() != admin
            or not stat.S_ISDIR((common / "objects").lstat().st_mode)
            or (common / "objects").resolve() != common / "objects"):
        raise ValueError("invalid shared Git metadata directory")
    if hashlib.sha256(_read(project / ".git", MAX_POINTER)).hexdigest() != value["pointer_sha256"]:
        raise ValueError("Git worktree pointer changed before launch")
    _read(admin / "commondir", MAX_POINTER)
    _read(admin / "HEAD", MAX_POINTER)
    _read(common / "config", MAX_CONFIG)
    return dict(value, common=str(common))


def bind_arguments(value: dict, resources, inherited: list[int]) -> list[str]:
    common = Path(value["common"])
    guest_admin = GUEST_COMMON + "/" + value["relative"]
    argv = ["--ro-bind", str(common), GUEST_COMMON]

    def bind(data: bytes, destination: str) -> None:
        stream = resources.enter_context(tempfile.TemporaryFile())
        stream.write(data)
        stream.flush()
        stream.seek(0)
        inherited.append(stream.fileno())
        argv.extend(["--ro-bind-data", str(stream.fileno()), destination])

    bind(("gitdir: " + guest_admin + "\n").encode(), "/workspace/.git")
    bind((GUEST_COMMON + "\n").encode(), guest_admin + "/commondir")
    config = common.joinpath(*PurePosixPath(value["relative"]).parts) / "config.worktree"
    if config.exists():
        # A per-worktree absolute core.worktree must name the guest workspace.
        bind(_read(config, MAX_CONFIG) + b"\n[core]\n\tworktree = /workspace\n",
             guest_admin + "/config.worktree")
    return argv
