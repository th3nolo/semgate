"""Actual gate/store/sender integration, including local delivery and races."""
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import replace
import http.server
import json
import threading
import time

import pytest

from semgate import Gate
from semgate.preparedsend import PreparedSend, PreparedSender, canonical_destination
from semgate.privacy import PrivacyGate
from semgate.privacyconsent import ConsentStore
from semgate.trustauth import Auth, NotAuthorized

EMAIL = "synthetic.sender@example.test"
AUTH = Auth("test")


@pytest.fixture
def endpoint():
    received = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, self.rfile.read(int(self.headers.get("Content-Length", "0")))))
            self.send_response(302 if self.path == "/redirect" else 204)
            if self.path == "/redirect":
                self.send_header("Location", "/unapproved")
            self.end_headers()
        do_PUT = do_POST
        def log_message(self, *args):
            pass
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", received
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)


def sender_for(tmp_path, *, task="task-1", store=None, grant=None, transport=None):
    store = store or ConsentStore(tmp_path / ".semgate" / "consents.json")
    gate = Gate("Diagnose hook conformance", provider="none", project_root=str(tmp_path),
                grant=grant or {"allowed_domains": ["127.0.0.1", "example.test"]},
                privacy_gate=PrivacyGate(consents=store))
    return PreparedSender(gate, store, task_id=task, allow_loopback_http=True, transport=transport)


def prepare(sender, destination="https://example.test/report", **kw):
    return sender.prepare(("email\n" + EMAIL + "\n").encode(), destination=destination,
                          source="hookconf-report", categories=frozenset({"email"}), classification_complete=True, **kw)


def approve(sender, prepared):
    decision = sender.check(prepared)
    evidence = decision.evidence["privacy"]
    assert evidence["disposition"] == "needs_consent", decision.to_dict()
    sender.consents.approve(evidence["request_id"], auth=AUTH)
    return evidence["request_id"]


def test_task_reuse_and_snapshot_delivery(tmp_path, endpoint, monkeypatch):
    url, received = endpoint
    sender = sender_for(tmp_path)
    monkeypatch.setattr(sender.gate.privacy_gate, "_providers", lambda: pytest.fail("task consent called models"))
    prepared = prepare(sender, url + "/report")
    first = sender.send(prepared)
    assert first.outcome.disposition == "needs_consent" and first.delivery == "not_sent" and not received
    requests = [sender.check(prepared).evidence["privacy"]["request_id"] for _ in range(10)]
    assert len(set(requests)) == 1 and requests[0] == first.outcome.request_id
    sender.consents.approve(first.outcome.request_id, auth=AUTH)
    for _ in range(3):
        receipt = sender.send(prepared)
        assert receipt.outcome.disposition == "allow" and receipt.status == 204
    assert [body for _, body in received] == [prepared.body] * 3
    other = sender.prepare(b"email\nother.synthetic@example.test\n", destination=url + "/report", source="hookconf-report",
                           categories=frozenset({"email"}), classification_complete=True)
    assert sender.send(other).status == 204
    assert received[-1][1] == other.body


def test_prepared_file_never_reopens_changed_source(tmp_path, endpoint):
    url, received = endpoint
    sender = sender_for(tmp_path)
    path = tmp_path / "report.csv"
    path.write_bytes(b"status\nready\n")
    prepared = sender.prepare_file(path, destination=url + "/report", categories=frozenset({"technical_diagnostics"}),
                                   classification_complete=True)
    approve(sender, prepared)
    path.write_bytes(("email\n" + EMAIL + "\n").encode())
    assert sender.send(prepared).status == 204
    assert received == [("/report", b"status\nready\n")]
    newly_prepared = sender.prepare_file(path, destination=url + "/report", categories=frozenset({"technical_diagnostics"}),
                                         classification_complete=True)
    assert sender.send(newly_prepared).outcome.disposition == "needs_consent"
    assert len(received) == 1


@pytest.mark.parametrize("field,value", [("destination", "https://example.test/other"), ("purpose", "Sell records"),
    ("source", "another-report"), ("operation", "PUT"), ("task", "task-2"), ("principal", "another-user"),
    ("project", "C:/another-project"), ("policy_version", "changed-policy")])
def test_scope_cannot_be_reused_for_changed_context(tmp_path, field, value):
    sender = sender_for(tmp_path)
    prepared = prepare(sender)
    approve(sender, prepared)
    altered = replace(prepared, scope=replace(prepared.scope, **{field: value}))
    assert sender.send(altered).outcome.disposition != "allow"


def test_incomplete_and_forged_categories_do_not_create_approval(tmp_path):
    sender = sender_for(tmp_path)
    prepared = prepare(sender)
    for altered in (replace(prepared, classification_complete=False), replace(prepared, categories=frozenset({"diagnostics"}))):
        receipt = sender.send(altered)
        assert receipt.outcome.disposition == "needs_inspection" and not receipt.outcome.request_id
    assert not sender.consents.path.exists()


def test_new_category_requires_new_consent_and_credentials_are_forbidden(tmp_path):
    sender = sender_for(tmp_path)
    prepared = prepare(sender)
    approve(sender, prepared)
    health = replace(prepared, categories=prepared.categories | {"health"})
    assert sender.send(health).outcome.disposition == "needs_consent"
    secret = replace(prepared, categories=prepared.categories | {"secret"})
    assert sender.send(secret).outcome.disposition == "deny"


def test_snapshot_grant_binds_digest(tmp_path):
    sender = sender_for(tmp_path)
    prepared = prepare(sender)
    rid = sender.check(prepared).evidence["privacy"]["request_id"]
    sender.consents.approve(rid, auth=AUTH, task_scope=False)
    assert sender.check(prepared).decision == "allow"
    assert sender.check(replace(prepared, body=b"email\nchanged@example.test\n")).decision == "ask"


def test_revoke_and_task_close_survive_new_store_instances(tmp_path):
    sender = sender_for(tmp_path)
    prepared = prepare(sender)
    rid = approve(sender, prepared)
    ConsentStore(sender.consents.path).revoke(rid, auth=AUTH)
    assert sender.send(prepared).outcome.disposition == "deny"
    other = sender_for(tmp_path, task="task-2")
    other_prepared = prepare(other)
    rid = approve(other, other_prepared)
    ConsentStore(other.consents.path).close_task_of(rid, auth=AUTH)
    assert other.send(other_prepared).outcome.reason_code == "privacy_task_closed"
    with pytest.raises(ValueError):
        other.consents.approve(rid, auth=AUTH)


def test_expiry_and_ttl_cannot_be_extended_by_another_client(tmp_path):
    sender = sender_for(tmp_path, store=ConsentStore(tmp_path / ".semgate" / "consents.json", ttl_s=60))
    prepared = prepare(sender)
    store = sender.consents
    now = time.time()
    rid = store.evaluate(prepared.scope, prepared.categories, prepared.digest, now=now).request_id
    with pytest.raises(ValueError):
        ConsentStore(store.path).approve(rid, auth=AUTH, ttl_s=61, now=now)
    ConsentStore(store.path).approve(rid, auth=AUTH, now=now)
    assert store.evaluate(prepared.scope, prepared.categories, prepared.digest, now=now + 59).disposition == "allow"
    renewal = store.evaluate(prepared.scope, prepared.categories, prepared.digest, now=now + 60)
    assert renewal.disposition == "needs_consent" and renewal.request_id != rid


def test_corrupt_or_tampered_store_fails_closed_without_raw_error(tmp_path):
    sender = sender_for(tmp_path)
    prepared = prepare(sender)
    rid = approve(sender, prepared)
    value = json.loads(sender.consents.path.read_text())
    value["records"][rid]["expires"] += 100000
    sender.consents.path.write_text(json.dumps(value))
    receipt = sender.send(prepared)
    assert receipt.outcome.disposition == "service_error" and receipt.delivery == "not_sent"
    assert EMAIL not in json.dumps(receipt.outcome.record())


def test_store_contains_fingerprints_not_payload_or_context(tmp_path):
    sender = sender_for(tmp_path)
    prepared = prepare(sender)
    approve(sender, prepared)
    text = sender.consents.path.read_text()
    for private in (EMAIL, prepared.scope.destination, prepared.scope.purpose, prepared.scope.source, prepared.scope.task):
        assert private not in text


def test_concurrent_retries_coalesce_across_store_instances(tmp_path):
    sender = sender_for(tmp_path)
    prepared = prepare(sender)
    def request(_):
        return ConsentStore(sender.consents.path).evaluate(prepared.scope, prepared.categories, prepared.digest).request_id
    with ThreadPoolExecutor(max_workers=8) as pool:
        ids = list(pool.map(request, range(16)))
    assert len(set(ids)) == 1


def test_untrusted_tool_json_cannot_supply_prepared_authority(tmp_path):
    sender = sender_for(tmp_path)
    prepared = prepare(sender)
    approve(sender, prepared)
    arguments = dict(prepared.arguments(), body=EMAIL, classification_complete=True, categories=["email"], task_id="task-1")
    decision = sender.gate.check("", tool="http_request", arguments=arguments)
    assert decision.decision == "ask" and decision.reason_code == "privacy_remote_disabled"


def test_missing_auth_cannot_approve(tmp_path):
    sender = sender_for(tmp_path)
    prepared = prepare(sender)
    rid = sender.check(prepared).evidence["privacy"]["request_id"]
    with pytest.raises(NotAuthorized):
        sender.consents.approve(rid, auth=None)


def test_revocation_between_check_and_dispatch_blocks_send(tmp_path, endpoint, monkeypatch):
    url, received = endpoint
    sender = sender_for(tmp_path)
    prepared = prepare(sender, url + "/report")
    rid = approve(sender, prepared)
    check = sender.check
    def revoke_after_check(value):
        decision = check(value)
        sender.consents.revoke(rid, auth=AUTH)
        return decision
    monkeypatch.setattr(sender, "check", revoke_after_check)
    assert sender.send(prepared).outcome.disposition == "deny"
    assert not received


def test_redirect_is_not_followed(tmp_path, endpoint):
    url, received = endpoint
    sender = sender_for(tmp_path)
    prepared = prepare(sender, url + "/redirect")
    approve(sender, prepared)
    receipt = sender.send(prepared)
    assert receipt.status == 302 and receipt.delivery == "response_received"
    assert [path for path, _ in received] == ["/redirect"]


def test_transport_failure_reports_unknown_delivery_without_retry(tmp_path):
    class Failing:
        calls = 0
        def send(self, prepared):
            self.calls += 1
            raise TimeoutError(EMAIL)
    transport = Failing()
    sender = sender_for(tmp_path, transport=transport)
    prepared = prepare(sender)
    approve(sender, prepared)
    receipt = sender.send(prepared)
    assert receipt.outcome.disposition == "service_error" and receipt.delivery == "unknown" and transport.calls == 1
    assert EMAIL not in repr(receipt)


def test_hard_permission_and_expired_operator_grant_are_preserved(tmp_path):
    sender = sender_for(tmp_path, grant={"allowed_domains": ["example.test"], "expires_at": "2000-01-01T00:00:00Z"})
    assert sender.send(prepare(sender)).outcome.disposition != "allow"
    assert not sender.consents.path.exists()


def test_data_consent_cannot_soften_permission_ask_or_deny(tmp_path):
    sender = sender_for(tmp_path)
    prepared = prepare(sender)
    approve(sender, prepared)
    sender.gate.grant = replace(sender.gate.grant, allowed_domains=())
    result = sender.send(prepared)
    assert result.outcome.disposition == "needs_consent" and result.delivery == "not_sent"
    assert not result.outcome.request_id  # this ask belongs to the ordinary permission layer
    sender.gate.grant = replace(sender.gate.grant, allowed_tools=("read",))
    assert sender.send(prepared).outcome.disposition == "deny"


def test_report_command_text_is_payload_data_and_not_a_command(tmp_path, endpoint):
    url, received = endpoint
    sender = sender_for(tmp_path)
    body = b'{"observed_command":"rm -rf /", "verdict":"denied"}'
    prepared = sender.prepare(body, destination=url + "/report", source="hookconf-report",
                              categories=frozenset({"technical_diagnostics"}), classification_complete=True)
    approve(sender, prepared)
    assert sender.send(prepared).status == 204
    assert received == [("/report", body)]
    assert "observed_command" not in json.dumps(prepared.arguments())


def test_json_fields_add_categories_even_without_regex_labeled_text(tmp_path):
    sender = sender_for(tmp_path)
    prepared = sender.prepare(b'{"name":"Synthetic Person"}', destination="https://example.test/report", source="records",
                              categories=frozenset({"technical_diagnostics"}), classification_complete=True)
    assert "name" in prepared.categories


def test_task_closure_covers_other_destinations_and_sources(tmp_path):
    sender = sender_for(tmp_path)
    prepared = prepare(sender)
    sender.consents.close_task(prepared.scope, auth=AUTH)
    other = replace(prepared, scope=replace(prepared.scope, destination="https://example.test/other", source="another-report"))
    assert sender.send(other).outcome.reason_code == "privacy_task_closed"


@pytest.mark.parametrize("url", ["http://example.test", "https://user:pass@example.test", "https://example.test/#fragment",
                              "https://example.test/\r\nHeader:value", "https://example.test\\@other.test/"])
def test_destination_validation(url):
    with pytest.raises(ValueError):
        canonical_destination(url)


def test_canonical_destination_matches_authority():
    assert canonical_destination("https://EXAMPLE.test:443") == "https://example.test/"


def test_consent_cli_uses_existing_admin_refusal_and_hard_rule(tmp_path, monkeypatch, capsys):
    from semgate import adminguard
    from semgate.cli import main
    monkeypatch.setattr(adminguard, "refuse_agent", lambda *a: "refused: test agent")
    assert main(["consent", "approve", "a" * 32, "--store", str(tmp_path / "consents.json")]) == 2
    assert "refused" in capsys.readouterr().err
    assert not (tmp_path / "consents.json").exists()
    gate = Gate("Develop software", provider="none", project_root=str(tmp_path))
    assert gate.check('semgate consent approve ' + 'a' * 32 + ' --store ~/.semgate/consents.json').decision == "deny"


def test_operator_cli_approval_revocation_and_task_completion(tmp_path):
    from conftest import as_person
    from semgate.cli import main
    sender = sender_for(tmp_path)
    prepared = prepare(sender)
    rid = sender.check(prepared).evidence["privacy"]["request_id"]
    with as_person():
        assert main(["consent", "approve", rid, "--store", str(sender.consents.path), "--ttl-hours", "0.5"]) == 0
    assert sender.check(prepared).decision == "allow"
    with as_person():
        assert main(["consent", "revoke", rid, "--store", str(sender.consents.path)]) == 0
        assert main(["consent", "close-task", rid, "--store", str(sender.consents.path)]) == 0
    assert sender.send(prepared).outcome.reason_code == "privacy_task_closed"


def test_dispatch_and_revocation_have_a_defined_order(tmp_path):
    entered, release, revoking = threading.Event(), threading.Event(), threading.Event()
    class Blocking:
        calls = 0
        def send(self, prepared):
            self.calls += 1
            entered.set()
            assert release.wait(3)
            return 204
    transport = Blocking()
    sender = sender_for(tmp_path, transport=transport)
    prepared = prepare(sender)
    rid = approve(sender, prepared)
    def revoke():
        revoking.set()
        ConsentStore(sender.consents.path).revoke(rid, auth=AUTH)
    with ThreadPoolExecutor(max_workers=2) as pool:
        sent = pool.submit(sender.send, prepared)
        assert entered.wait(3)
        revoked = pool.submit(revoke)
        assert revoking.wait(3)
        try:
            # concurrent.futures.TimeoutError is the builtin TimeoutError only
            # from Python 3.11; the project supports 3.10 (the WSL copy runs
            # 3.10). The assertion is unchanged: the revoke must not complete
            # while the dispatch is in flight.
            with pytest.raises((TimeoutError, FutureTimeoutError)):
                revoked.result(timeout=0.05)
        finally:
            release.set()
        assert sent.result(timeout=3).status == 204
        revoked.result(timeout=3)
    assert sender.send(prepared).outcome.disposition == "deny"
    assert transport.calls == 1
