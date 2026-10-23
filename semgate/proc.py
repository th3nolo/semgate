"""Start child processes without a console window.

On Windows a console program (git, python, ps) started from a process that
has no console of its own gets a new, visible console window. A hook runs
inside an agent host, often without a console, so every `git` call semgate
makes could flash a black window. `run` adds CREATE_NO_WINDOW on Windows and
is otherwise `subprocess.run`; `popen` applies the same rule to supervised
processes. tests/test_hidden_processes.py fails when code
in semgate/ calls subprocess directly, or when a plugin asset spawns a
process without `windowsHide: true`.
"""
from __future__ import annotations

import os
import subprocess
from typing import Any

CREATE_NO_WINDOW = 0x08000000


def run(args: Any, **kwargs: Any) -> "subprocess.CompletedProcess[Any]":
    if os.name == "nt":
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | CREATE_NO_WINDOW
    return subprocess.run(args, **kwargs)


def popen(args: Any, **kwargs: Any) -> "subprocess.Popen[Any]":
    if os.name == "nt":
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | CREATE_NO_WINDOW
    return subprocess.Popen(args, **kwargs)
