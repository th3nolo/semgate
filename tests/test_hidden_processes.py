"""No visible console windows from semgate.

Found live (2026-09-25): OpenCode's service started `semgate serve` from the
plugin without windowsHide, and a black console window stayed open on the
user's desktop. Every process semgate starts must be hidden:

  * plugin assets (JS/TS) pass `windowsHide: true` to every spawn/exec call;
  * Python code in semgate/ starts processes only through semgate.proc.run,
    which adds CREATE_NO_WINDOW on Windows.
"""
import os
import re
import subprocess
from pathlib import Path

import semgate
import pytest
from semgate import proc

PKG = Path(semgate.__file__).resolve().parent
SPAWN = re.compile(r"\b(spawn|spawnSync|execFile|execFileSync|exec|execSync|fork)\s*\(")
DIRECT = re.compile(r"\bsubprocess\.(run|Popen|call|check_call|check_output)\s*\(|\bos\.(system|popen|spawn\w*)\s*\(")


def _call_text(src: str, start: int) -> str:
    """The text of a call from its opening parenthesis to the matching close."""
    i = src.index("(", start)
    depth = 0
    for j in range(i, len(src)):
        depth += {"(": 1, ")": -1}.get(src[j], 0)
        if depth == 0:
            return src[i:j + 1]
    return src[i:]


def test_every_asset_spawn_is_hidden():
    found = 0
    for path in sorted((PKG / "assets").glob("*")):
        if path.suffix not in (".js", ".ts", ".mjs", ".cjs"):
            continue
        src = path.read_text(encoding="utf-8")
        for m in SPAWN.finditer(src):
            if src[max(0, m.start() - 1)] in ".":        # a method like proc.exec( on another object
                continue
            found += 1
            call = _call_text(src, m.start())
            assert "windowsHide: true" in call, f"{path.name}: {m.group(1)} without windowsHide: true: {call[:160]}"
    assert found >= 2, "expected the OpenCode and Pi spawns; did the assets move?"


START = {("subprocess", n) for n in ("run", "Popen", "call", "check_call", "check_output")} | \
        {("os", n) for n in ("system", "popen", "spawnl", "spawnv", "spawnve", "spawnlp", "spawnvp", "startfile")}


def _direct_calls(src: str):
    """(line, name) of real calls such as subprocess.run(...) — parsed, so
    text in strings and docstrings does not count."""
    import ast
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and isinstance(node.func.value, ast.Name) and (node.func.value.id, node.func.attr) in START:
            yield node.lineno, f"{node.func.value.id}.{node.func.attr}"


def test_python_code_starts_processes_only_through_proc_run():
    offenders = []
    for path in sorted(PKG.rglob("*.py")):
        rel = path.relative_to(PKG).as_posix()
        if rel == "proc.py" or rel.startswith("eval/"):   # eval runners are developer tools, not hook paths
            continue
        offenders += [f"{rel}:{n}: {name}(...)" for n, name in _direct_calls(path.read_text(encoding="utf-8"))]
    assert not offenders, "use semgate.proc.run (hidden on Windows):\n" + "\n".join(offenders)


def test_the_python_check_catches_a_direct_call():
    assert list(_direct_calls("import subprocess\nsubprocess.run(['git'])\n")) == [(2, "subprocess.run")]
    assert list(_direct_calls('"""mentions os.system("x") in text"""\n')) == []


@pytest.mark.parametrize("factory,method", [(proc.run, "run"), (proc.popen, "Popen")])
def test_proc_run_adds_create_no_window_on_windows(monkeypatch, factory, method):
    seen = {}

    def fake_run(args, **kw):
        seen.update(kw)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, method, fake_run)
    monkeypatch.setattr(os, "name", "nt")
    factory(["git", "status"], capture_output=True)
    assert seen["creationflags"] & proc.CREATE_NO_WINDOW
    seen.clear()
    monkeypatch.setattr(os, "name", "posix")
    factory(["git", "status"])
    assert "creationflags" not in seen
