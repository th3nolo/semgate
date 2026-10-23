"""Canary: inside the test suite no real API key is reachable.

Found 2026-09-25: after semgate's own .env started to win over environment
variables, three tests picked up the developer's real TypeSafe key from the
checkout's .env, and a pytest assertion printed part of it. conftest sets
SEMGATE_SKIP_CHECKOUT_ENV=1 and clears the key variables for every test; this
file fails if that isolation breaks, in-process and in a subprocess.
"""
import os
import subprocess
import sys

from semgate.providers import keys


def test_no_key_is_found_in_process():
    for name in ("TYPESAFE_API_KEY", "OPENROUTER_API_KEY", "SUBQ_API_KEY"):
        assert keys.find_key(name) == ("", ""), name
    assert all(label != keys.CHECKOUT_LABEL for label, _ in keys.env_files())


def test_no_key_is_found_in_a_subprocess():
    code = ("from semgate.providers import keys; "
            "print(repr([keys.find_key(n)[1] for n in ('TYPESAFE_API_KEY', 'OPENROUTER_API_KEY', 'SUBQ_API_KEY')]))")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60, env=dict(os.environ))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "['', '', '']", out.stdout


def test_the_skip_only_drops_the_real_checkout_file(tmp_path, monkeypatch):
    fake = tmp_path / "checkout.env"
    fake.write_text("OPENROUTER_API_KEY=from-a-test-file\n", encoding="utf-8")
    monkeypatch.setattr(keys, "CHECKOUT_ENV", fake)          # a test's own file still counts
    assert keys.find_key("OPENROUTER_API_KEY")[0] == "from-a-test-file"
