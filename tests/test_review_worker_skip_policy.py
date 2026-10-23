"""Optional platform fixtures have exact skip rules and negative controls."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("review_localci", ROOT / "scripts/localci.py")
localci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(localci)
CASES = [
    ("optional existing Linux uv executable", ("posix", "wsl")),
    ("optional case-insensitive fixture parent", ("posix", "wsl")),
    ("PowerShell parser unavailable; this check is exercised on Windows CI", ("posix", "wsl")),
    ("symlink privilege unavailable", ("windows",)),
]


@pytest.mark.parametrize("side", ["windows", "posix", "wsl"])
@pytest.mark.parametrize("reason,sides", CASES)
def test_fixture_skip_matches_only_its_declared_platforms(side, reason, sides):
    assert localci.skip_allowed(reason, side, localci.read_allowed_skips()) is (side in sides)


@pytest.mark.parametrize("side", ["windows", "posix", "wsl"])
def test_unexpected_fixture_skips_still_fail_membership(side):
    rules = localci.read_allowed_skips()
    assert not localci.skip_allowed("unexpected missing security fixture", side, rules)
    for reason, _ in CASES:
        assert not localci.skip_allowed(reason + " with an unexpected suffix", side, rules)


@pytest.mark.parametrize("side", ["windows", "posix", "wsl"])
def test_real_local_validation_check_accepts_only_declared_optional_skips(tmp_path, side):
    report = tmp_path / "junit.xml"
    def write(reason):
        report.write_text('<testsuite><testcase name="passed"/><testcase name="optional">'
                          '<skipped message="' + reason + '"/></testcase></testsuite>')
    for reason, sides in CASES:
        if side in sides:
            write(reason)
            ok, _, _ = localci.check(side, "tests", report, floors={side + ".tests": 1})
            assert ok
    write("unexpected missing security fixture")
    ok, summary, _ = localci.check(side, "tests", report, floors={side + ".tests": 1})
    assert not ok and "skip reason not in tests/.allowed_skips" in summary
