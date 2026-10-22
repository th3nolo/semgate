"""Explicit HTTP disclosure boundary: prepare, inspect, authorize, send same bytes.

The trusted host supplies complete schema/provenance labels and task identity.
An agent-supplied classification_complete flag in ordinary tool JSON has no
authority. This API does not intercept arbitrary shell/network execution.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Protocol
from urllib.error import HTTPError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .privacyconsent import ConsentOutcome, DisclosureScope, POLICY_VERSION, validate_categories
from .privacydata import MAX_TEXT
from .privacyinspect import Inspection, inspect

if TYPE_CHECKING:
    from .envelope import Envelope
    from .gate import Gate
    from .judge import Decision
    from .privacyconsent import ConsentStore


def canonical_destination(url: str, *, allow_loopback_http: bool = False) -> str:
    if not isinstance(url, str) or len(url) > 8192 or any(ord(c) <= 32 or ord(c) == 127 for c in url) or "\\" in url:
        raise ValueError("invalid disclosure destination")
    parts = urlsplit(url)
    if not parts.hostname or parts.username is not None or parts.password is not None or parts.fragment:
        raise ValueError("destination must have a host and no credentials or fragment")
    host = parts.hostname.encode("idna").decode("ascii").lower()
    if parts.scheme != "https":
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not (parts.scheme == "http" and allow_loopback_http and loopback):
            raise ValueError("disclosures require HTTPS; HTTP is available only for explicit loopback tests")
    port = parts.port
    host = f"[{host}]" if ":" in host else host
    authority = host if port in (None, 443 if parts.scheme == "https" else 80) else f"{host}:{port}"
    return urlunsplit((parts.scheme, authority, parts.path or "/", parts.query, ""))


@dataclass(frozen=True)
class PreparedSend:
    scope: DisclosureScope
    body: bytes
    categories: frozenset[str]
    classification_complete: bool = False

    def __post_init__(self) -> None:
        if type(self.body) is not bytes or len(self.body) > MAX_TEXT:
            raise ValueError("prepared payload must be immutable bounded bytes")
        self.body.decode("utf-8-sig")
        validate_categories(self.categories)
        if not isinstance(self.classification_complete, bool) or self.scope.operation not in {"POST", "PUT"}:
            raise ValueError("invalid prepared disclosure")

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    def arguments(self) -> dict:
        return {"url": self.scope.destination, "method": self.scope.operation,
                "payload_sha256": self.digest, "payload_bytes": len(self.body), "source": self.scope.source}

    def inspect(self, envelope: Envelope) -> Inspection:
        """Inspect body locally; ordinary permission rules/providers see only effect metadata."""
        from dataclasses import replace
        from .envelope import ProposedAction
        text = self.body.decode("utf-8-sig")
        try:
            body = json.loads(text)
        except ValueError:
            body = text
        action = ProposedAction("http_request", {**self.arguments(), "body": body})
        return inspect(replace(envelope, action=action))

    def matches(self, envelope: Envelope) -> bool:
        from .feedback import norm_root
        return (envelope.action.tool == "http_request" and dict(envelope.action.arguments) == self.arguments()
                and envelope.grant.principal == self.scope.principal and envelope.grant.purpose == self.scope.purpose
                and norm_root(envelope.environment.project_root) == self.scope.project)


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SendTransport(Protocol):
    def send(self, prepared: PreparedSend) -> int: ...


class HTTPTransport:
    """No proxy environment, redirects, retries, cookies, response body or auth forwarding."""
    def __init__(self, timeout_s: float = 5.0) -> None:
        import math
        if isinstance(timeout_s, bool) or not math.isfinite(timeout_s) or not 0 < timeout_s <= 30:
            raise ValueError("sender timeout must be positive and at most 30 seconds")
        self.timeout_s = timeout_s

    def send(self, prepared: PreparedSend) -> int:
        request = Request(prepared.scope.destination, data=prepared.body, method=prepared.scope.operation,
                          headers={"Content-Type": "application/octet-stream"})
        opener = build_opener(ProxyHandler({}), _NoRedirect())
        try:
            with opener.open(request, timeout=self.timeout_s) as response:
                return response.status
        except HTTPError as error:
            # A response arrived, including an unfollowed redirect. Its body
            # and exception text are deliberately not read or returned.
            status = error.code
            error.close()
            return status


@dataclass(frozen=True)
class SendReceipt:
    outcome: ConsentOutcome
    delivery: str = "not_sent"  # response_received | unknown (transport failure after dispatch)
    status: Optional[int] = None
    digest: str = ""


class PreparedSender:
    def __init__(self, gate: Gate, consents: ConsentStore, *, task_id: str,
                 allow_loopback_http: bool = False, transport: Optional[SendTransport] = None) -> None:
        from .privacy import PrivacyGate
        if not isinstance(gate.privacy_gate, PrivacyGate) or gate.privacy_gate.consents is not consents:
            raise ValueError("sender and gate must share the same opt-in privacy consent store")
        if not isinstance(task_id, str) or not task_id.strip():
            raise ValueError("sender needs a trusted task id")
        self.gate, self.consents, self.task_id = gate, consents, task_id
        self.allow_loopback_http = allow_loopback_http
        self.transport = transport or HTTPTransport()

    def prepare(self, body: bytes, *, destination: str, source: str, categories: frozenset[str],
                classification_complete: bool = False, method: str = "POST") -> PreparedSend:
        """Host-side classification assertion; never copy it from agent/tool arguments."""
        url = canonical_destination(destination, allow_loopback_http=self.allow_loopback_http)
        scope = DisclosureScope(self.gate.grant.principal, self.gate.project_root, self.task_id, source, method,
                                url, self.gate.grant.purpose, POLICY_VERSION + ":" + self.gate.policy.version)
        prepared = PreparedSend(scope, body, categories, classification_complete)
        # Local signals always add categories, even if the host omitted them.
        evidence = prepared.inspect(self.gate.envelope("", tool="http_request", arguments=prepared.arguments()))
        found = frozenset(c for c in evidence.cleaner.counts if c != "home")
        return PreparedSend(scope, body, categories | found, classification_complete and evidence.complete)

    def prepare_file(self, path: Path, *, destination: str, categories: frozenset[str],
                     classification_complete: bool = False, method: str = "POST") -> PreparedSend:
        # Read exactly once through the existing bounded project/grant inspector.
        evidence = inspect(self.gate.envelope("", tool="upload", arguments={"file": str(path), "url": destination}))
        if not evidence.complete or len(evidence.payloads) != 1:
            raise ValueError("file payload could not be completely inspected")
        resolved, body = next(iter(evidence.payloads.items()))
        found = frozenset(c for c in evidence.cleaner.counts if c != "home")
        return self.prepare(body, destination=destination, source=str(resolved), categories=categories | found,
                            classification_complete=classification_complete, method=method)

    def check(self, prepared: PreparedSend) -> Decision:
        if (prepared.scope.task != self.task_id
                or prepared.scope.policy_version != POLICY_VERSION + ":" + self.gate.policy.version
                or canonical_destination(prepared.scope.destination, allow_loopback_http=self.allow_loopback_http) != prepared.scope.destination):
            from .judge import Decision
            return Decision("deny", stage="privacy", reason_code="privacy_prepared_scope_mismatch")
        return self.gate.check_prepared(prepared)

    def send(self, prepared: PreparedSend) -> SendReceipt:
        decision = self.check(prepared)
        privacy = decision.evidence.get("privacy", {})
        if decision.decision != "allow":
            disposition = "deny" if decision.decision == "deny" else privacy.get("disposition", "needs_consent")
            if disposition == "allow":
                # Privacy consent cannot soften an ordinary permission ask.
                disposition = "needs_consent"
            return SendReceipt(ConsentOutcome(disposition, decision.reason_code, privacy.get("request_id", "")), digest=prepared.digest)
        # Permission is checked again above; consent is re-read under the same
        # cross-process lock used by revocation and task closure at dispatch.
        dispatched = False

        class GrantExpired(Exception):
            pass

        def dispatch() -> int:
            nonlocal dispatched
            if self.gate.grant.is_expired():
                raise GrantExpired()
            dispatched = True
            return self.transport.send(prepared)
        try:
            outcome, status = self.consents.use(prepared.scope, prepared.categories, prepared.digest, dispatch)
            return SendReceipt(outcome, "response_received" if status is not None else "not_sent", status, prepared.digest)
        except GrantExpired:
            return SendReceipt(ConsentOutcome("deny", "privacy_operator_grant_expired"), digest=prepared.digest)
        except Exception:
            # Dispatch may have reached the receiver. Do not assert no delivery
            # or retry automatically after a timeout/lost response.
            return SendReceipt(ConsentOutcome("service_error", "privacy_send_error"),
                               "unknown" if dispatched else "not_sent", digest=prepared.digest)
