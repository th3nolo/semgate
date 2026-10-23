"""Optional worker fixtures have narrow skip exceptions, with negative controls."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("review_localci", ROOT / "scripts/localci.py")
localci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(localci)
REASONS = ["optional existing Linux uv executable", "optional case-insensitive fixture parent"]


@pytest.mark.parametrize("side", ["posix", "wsl"])
@pytest.mark.parametrize("reason", REASONS)
def test_declared_optional_linux_fixture_skip_is_recognized(side, reason):
    assert localci.skip_allowed(reason, side, localci.read_allowed_skips())


@pytest.mark.parametrize("reason", REASONS)
def test_optional_linux_fixture_exception_does_not_apply_to_windows(reason):
    assert not localci.skip_allowed(reason, "windows", localci.read_allowed_skips())


@pytest.mark.parametrize("side", ["windows", "posix", "wsl"])
def test_unexpected_fixture_skips_still_fail_membership(side):
    rules = localci.read_allowed_skips()
    assert not localci.skip_allowed("unexpected missing security fixture", side, rules)
    assert not localci.skip_allowed(REASONS[0] + " with an unexpected suffix", side, rules)


@pytest.mark.parametrize("side", ["posix", "wsl"])
def test_real_local_validation_check_accepts_only_declared_optional_skips(tmp_path, side):
    report = tmp_path / "junit.xml"
    def write(reason):
        report.write_text('<testsuite><testcase name="passed"/><testcase name="optional">'
                          '<skipped message="' + reason + '"/></testcase></testsuite>')
    for reason in REASONS:
        write(reason)
        ok, _, _ = localci.check(side, "tests", report, floors={side + ".tests": 1})
        assert ok
    write("unexpected missing security fixture")
    ok, summary, _ = localci.check(side, "tests", report, floors={side + ".tests": 1})
    assert not ok and "skip reason not in tests/.allowed_skips" in summary
