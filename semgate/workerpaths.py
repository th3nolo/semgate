"""The worker's POSIX project view, with bounded host-side evidence readers.

Only the trusted broker supplies this mapping. Commands remain byte-for-byte
unchanged: scope checks and the judge see the same /workspace namespace that
executes them; source and Git readers translate project paths back to the host.
"""
from dataclasses import replace
from pathlib import Path
import posixpath

from .gitstate import GitFacts, GitHistory, HistoryVerdict, TargetState
from .scriptsource import LocalWorkspace

ROOT = "/workspace"


class WorkerPaths:
    def __init__(self, project: str):
        self.project = Path(project).resolve()

    def host(self, path: str, cwd: str = ROOT) -> str:
        if any(c in path+cwd for c in "\\:\x00"):
            raise ValueError("unsupported worker path")
        guest = posixpath.normpath(posixpath.join(cwd, path))
        if guest != ROOT and not guest.startswith(ROOT+"/"):
            raise ValueError("path outside worker project")
        target = self.project.joinpath(*guest[len(ROOT):].strip("/").split("/"))
        if not target.resolve().is_relative_to(self.project):
            raise ValueError("worker path resolves outside host project")
        return str(target)

    def guest(self, host: str) -> str:
        relative = Path(host).relative_to(self.project).as_posix()
        return ROOT if relative == "." else ROOT+"/"+relative

    def within(self, path, prefixes, cwd):
        from .rules import path_within
        try:
            target = self.host(path, cwd)
            for prefix in prefixes:
                try:
                    if path_within(target, (self.host(prefix),)):
                        return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False

    def envelope(self, envelope):
        def prefix(value):
            path = Path(value).expanduser().resolve()
            if self.project.is_relative_to(path):
                return ROOT
            return self.guest(str(path)) if path.is_relative_to(self.project) else value
        arguments = dict(envelope.action.arguments)
        if envelope.action.tool == "write":
            arguments["path"] = self.guest(str(Path(arguments["path"])))
        return replace(envelope,
            grant=replace(envelope.grant, allowed_path_prefixes=tuple(prefix(p) for p in envelope.grant.allowed_path_prefixes)),
            environment=replace(envelope.environment, project_root=ROOT,
                                cwd=self.guest(str(Path(envelope.environment.cwd).resolve()))),
            action=replace(envelope.action, arguments=arguments))


class WorkerWorkspace(LocalWorkspace):
    def __init__(self, paths: WorkerPaths):
        self.paths = paths

    def is_dir(self, path, follow_links=True):
        try:
            return super().is_dir(self.paths.host(path), follow_links)
        except ValueError:
            return None

    def entry(self, path, project_root):
        try:
            return super().entry(self.paths.host(path), str(self.paths.project))
        except ValueError:
            return ""

    def list_files(self, folder, project_root, recursive=True, limit=5000, prune=None):
        try:
            files, complete = super().list_files(self.paths.host(folder), str(self.paths.project),
                                                 recursive, limit, prune)
            return [self.paths.guest(path) for path in files], complete
        except ValueError:
            return [], False

    def tool_program(self, path):
        return ""  # Host PATH programs do not describe the Linux worker.

    def tool_file(self, path, max_bytes=4096):
        return None

    def read(self, path, cwd, project_root):
        try:
            source, problem = super().read(self.paths.host(path, cwd), str(self.paths.project), str(self.paths.project))
            return (replace(source, path=ROOT+"/"+source.rel, run_cwd=cwd) if source else None), problem
        except ValueError:
            return None, "outside worker project"


class WorkerGitFacts(GitFacts):
    def __init__(self, paths, **kwargs):
        super().__init__(project_root=str(paths.project), **kwargs)
        self.paths = paths

    def state(self, path, cwd):
        try:
            state = super().state(self.paths.host(path, cwd), self.paths.host(cwd))
            return replace(state, path=path)
        except ValueError:
            return TargetState(path, "outside")


class WorkerGitHistory(GitHistory):
    def __init__(self, paths, **kwargs):
        super().__init__(**kwargs)
        self.paths = paths

    def check(self, kind, info, cwd):
        try:
            return super().check(kind, info, self.paths.host(cwd))
        except ValueError:
            return HistoryVerdict("unknown", detail="working directory outside worker project")
