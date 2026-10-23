import contextlib
import io
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from semgate.envelope import Envelope, Environment, ProposedAction, Trajectory, UserGrant
from semgate.policy import Policy

POLICY_PATH = ROOT / "policies" / "default_policy.json"
TRACES = ROOT / "fixtures" / "traces"
# The owner's live agy state (ledger, feedback, tool history). No test may write here.
LIVE_STATE = ROOT / ".antigravity" / "semgate"


def _live_state_snapshot():
    """{file name: (size, mtime_ns)} of LIVE_STATE/*.jsonl ({} when absent)."""
    out = {}
    if LIVE_STATE.is_dir():
        for path in sorted(LIVE_STATE.glob("*.jsonl")):
            try:
                st = path.stat()
            except OSError:
                continue
            out[path.name] = (st.st_size, st.st_mtime_ns)
    return out


@pytest.fixture(scope="session", autouse=True)
def _live_state_untouched():
    """Fails the session when any .antigravity/semgate/*.jsonl of the repo was
    created or changed during the run (a hook that wrote to the relative
    default ledger path with the repo as the current directory)."""
    before = _live_state_snapshot()
    yield
    after = _live_state_snapshot()
    changed = sorted(n for n in set(before) | set(after) if before.get(n) != after.get(n))
    if changed:
        pytest.fail(f"the test run wrote to the live state in {LIVE_STATE}: "
                    + ", ".join(f"{n} {before.get(n)} -> {after.get(n)}" for n in changed), pytrace=False)


@pytest.fixture(autouse=True)
def _writes_stay_in_pytest_tmp(monkeypatch, tmp_path_factory):
    """semgate.safemerge refuses to write outside SEMGATE_WRITE_ROOT. Every
    test gets the pytest temp root, so `semgate init` in a test can never
    touch the real ~/.claude, ~/.gemini, ~/.config/opencode, ~/.factory."""
    monkeypatch.setenv("SEMGATE_WRITE_ROOT", str(tmp_path_factory.getbasetemp()))


@pytest.fixture(autouse=True)
def _temp_home_and_cwd(monkeypatch, tmp_path_factory):
    """Every test (and every hook subprocess it starts, which inherits the
    environment and the current directory) runs with HOME and USERPROFILE in
    a temp dir and the current directory in another temp dir. A hook that
    falls back to ~/.semgate/<host>/ or to a path relative to the current
    directory then writes there, never to the owner's files or the repo.
    Tests that need their own HOME set it again (monkeypatch)."""
    home = tmp_path_factory.mktemp("home")
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    for var in ("SEMGATE_CONFIG", "SEMGATE_ANTIGRAVITY_CONFIG", "SEMGATE_LEDGER_FILE",
                "SEMGATE_TYPESAFE_API_KEY", "SEMGATE_OPENROUTER_API_KEY", "SEMGATE_SUBQ_API_KEY",
                "TYPESAFE_API_KEY", "OPENROUTER_API_KEY", "SUBQ_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    # The checkout's real .env holds the developer's keys: no test and no hook
    # subprocess may read it (tests/test_no_real_keys.py checks this).
    monkeypatch.setenv("SEMGATE_SKIP_CHECKOUT_ENV", "1")
    # `python -m semgate.<hook>` from the temp dir still imports this checkout.
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join(p for p in (str(ROOT), os.environ.get("PYTHONPATH", "")) if p))
    monkeypatch.chdir(tmp_path_factory.mktemp("cwd"))


@pytest.fixture(scope="session")
def policy():
    return Policy.load(str(POLICY_PATH))


def make_grant(**overrides):
    base = dict(
        grant_id="grant-test",
        principal="me",
        purpose="Fix the payment retry bug in src/payments and verify it with unit tests",
        allowed_tools=("read", "glob", "grep", "ls", "lsp", "bash", "edit", "write"),
        allowed_path_prefixes=("/home/me/proj",),
        allowed_domains=(),
        forbidden_patterns=(),
        issued_at="2026-09-18T07:00:00Z",
        expires_at="2026-09-19T00:00:00Z",
        provenance="test",
    )
    base.update(overrides)
    return UserGrant(**base)


def make_envelope(tool="edit", arguments=None, grant=None, project_root="/home/me/proj", evaluated_at="2026-09-18T08:00:00Z", trajectory=None):
    return Envelope(
        schema="semgate-envelope/1",
        action=ProposedAction(tool=tool, arguments=arguments or {"path": "/home/me/proj/src/payments/retry.py"}),
        grant=grant or make_grant(),
        environment=Environment(project_root=project_root, cwd=project_root, harness="test", session_id="ses-test"),
        trajectory=trajectory or Trajectory(recent=()),
        evaluated_at=evaluated_at,
    )


def load_trace(name):
    return json.loads((TRACES / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------- who runs `semgate trust add` (trustauth.py)

AGENT_HOST_PID = 910_000
from semgate import trustauth as _trustauth  # noqa: E402

REAL_ANCESTRY = _trustauth.ancestry          # the real reader, before the fixture below replaces it


def fake_chain(*procs):
    """A trustauth.Chain: this process first, then its parents (name, start)."""
    from semgate import trustauth
    chain = trustauth.Chain()
    pids = [os.getpid()] + [AGENT_HOST_PID + 100 + i for i in range(len(procs) - 1)]
    for i, (name, start) in enumerate(procs):
        chain.append(trustauth.Proc(pid=pids[i], ppid=pids[i + 1] if i + 1 < len(pids) else 0, name=name, start=start))
    return chain


@pytest.fixture(autouse=True)
def _trust_process_view(monkeypatch):
    """Every test runs as a tool call of an agent whose host process is
    `testagent` (a name trustauth does not know; semgate's hook records it),
    with no agent environment markers, whatever really started pytest (Claude
    Code, CI). The `human_terminal` fixture changes this to a person's own
    terminal. Caches of trustauth are cleared."""
    from semgate import trustauth
    for name in trustauth.ENV_MARKERS:
        monkeypatch.delenv(name, raising=False)
    chain = fake_chain(("python", "5003"), ("bash", "5002"), ("testagent", "5001"), ("windowsterminal", "5000"))
    monkeypatch.setattr(trustauth, "ancestry", lambda pid=None, limit=64: chain)
    monkeypatch.setattr(trustauth, "_hook_chain", {})
    monkeypatch.setattr(trustauth, "_noted", {})
    monkeypatch.setattr(trustauth, "_warned", {})
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(""))
    return chain


@contextlib.contextmanager
def as_person(answer="bakodi\n"):
    """`semgate trust add | file` typed by a person: parents pwsh <-
    WindowsTerminal <- explorer, no agent marker, and the person types
    `answer` when the CLI prints the word `bakodi`."""
    from semgate import trustauth
    chain = fake_chain(("python", "7003"), ("pwsh", "7002"), ("windowsterminal", "7001"), ("explorer", "7000"))
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(trustauth, "ancestry", lambda pid=None, limit=64: chain)
        mp.setattr(trustauth, "confirm_word", lambda rng=None: "bakodi")
        mp.setattr("sys.stdin", io.StringIO(answer * 20))
        yield chain


@pytest.fixture
def human_terminal():
    with as_person() as chain:
        yield chain
