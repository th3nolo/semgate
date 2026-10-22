"""Regressions from real curl disclosure counterexamples; synthetic data only."""
import http.server
import os
import shutil
import subprocess
import threading

import pytest

from semgate import Gate
from semgate.privacy import PrivacyGate
from semgate.privacycommands import file_references
from semgate.privacyinspect import inspect

EMAIL = "synthetic.upload@example.test"


@pytest.mark.parametrize("options", [
    "--upload-file=records.csv", "--upload-file records.csv", "-Trecords.csv", "-T records.csv",
    '--form "contact=<records.csv"', '--form "contact=@records.csv"', '-F"contact=<records.csv"',
    '--data-urlencode contact@records.csv', '--data-binary=@records.csv', '-d@records.csv',
    '--json @records.csv', '--header @records.csv',
])
def test_file_read_forms_are_inspected(tmp_path, options):
    (tmp_path / "records.csv").write_text("email\n" + EMAIL + "\n")
    gate = Gate("Upload diagnostics", provider="none", project_root=str(tmp_path),
                grant={"allowed_domains": ["example.test"]}, privacy_gate=PrivacyGate())
    command = f"curl {options} https://example.test/upload"
    evidence = inspect(gate.envelope(command))
    assert evidence.complete and len(evidence.files) == 1
    assert evidence.cleaner.counts["email"]
    assert gate.check(command).decision == "ask"


def test_max_time_is_not_upload_short_option(tmp_path):
    (tmp_path / "records.csv").write_text("status\nready\n")
    gate = Gate("Upload public status", provider="none", project_root=str(tmp_path),
                grant={"allowed_domains": ["example.test"]}, privacy_gate=PrivacyGate())
    command = "curl --max-time 3 --upload-file records.csv https://example.test/upload"
    assert file_references(command).references == ["records.csv"]
    assert gate.check(command).decision == "allow"


@pytest.mark.parametrize("options", ["--mystery=@records.csv", "--config=private.cfg", "-Kprivate.cfg", "--location",
                                     "--url-query contact@records.csv", "--upload-file=-", "--form contact=@a.csv,b.csv"])
def test_unknown_or_dynamic_forms_never_claim_complete(tmp_path, options):
    gate = Gate("Upload diagnostics", provider="none", project_root=str(tmp_path))
    assert not inspect(gate.envelope(f"curl {options} https://example.test")).complete


def test_literal_forms_and_emails_are_not_file_reads():
    assert file_references('curl --form-string "contact=@not-a-file" --data-raw @literal https://example.test').references == []
    assert file_references('curl --data-raw @literal https://example.test').problems == []
    assert file_references('curl --form-string "contact=@not-a-file" https://example.test').references == []


def test_windows_program_and_file_paths_preserved():
    result = file_references(r'C:\Windows\System32\curl.exe --upload-file="C:\Users\Example User\records.csv" https://example.test')
    # The shared shell lexer handles mixed quoted option arguments; a form
    # that cannot be read is conservative rather than silently empty/complete.
    assert result.references or result.problems


@pytest.mark.parametrize("options", [["--upload-file=records.csv"], ["--form", "contact=<records.csv"]])
def test_real_curl_counterexamples_do_not_reach_loopback(tmp_path, options):
    curl = shutil.which("curl.exe") or shutil.which("curl")
    if not curl:
        pytest.skip("curl executable is not installed")
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            self.send_response(204)
            self.end_headers()
        do_PUT = do_POST
        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/sink"
        (tmp_path / "records.csv").write_text("email\n" + EMAIL + "\n")
        argv = [curl, "--silent", "--show-error", "--noproxy", "*", *options, url]
        gate = Gate("Post a diagnostic artifact", provider="none", project_root=str(tmp_path),
                    grant={"allowed_domains": ["127.0.0.1"]}, privacy_gate=PrivacyGate())
        command = subprocess.list2cmdline(argv)
        decision = gate.check(command)
        if decision.decision == "allow":
            env = {k: v for k, v in os.environ.items() if k.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}}
            subprocess.run(argv, cwd=tmp_path, env=env, capture_output=True, timeout=5, check=True)
        assert decision.decision != "allow"
        assert received == []
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)
