"""Prepared execution in the real harness; snapshots stay in the server's memory.

Routes, identity and classification assertions belong to operator configuration.
Agent requests contain only route names or opaque snapshot ids. Never submit
dispatch to an abandonable judgment/deadline worker.
"""
from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import math
from pathlib import Path
import secrets
import threading
import time

from . import harness
from .envelope import UserGrant, canonical_json
from .gate import Gate
from .preparedsend import PreparedSend, PreparedSender
from .privacy import PrivacyGate
from .privacyconsent import ConsentStore, validate_categories
from .trustauth import Auth


class _HarnessGate(Gate):
    def __init__(self, broker: PreparedBroker) -> None:
        cfg = broker.config
        grant = UserGrant.from_dict(json.loads(Path(cfg["grant_file"]).read_text(encoding="utf-8")))
        super().__init__(grant.purpose, grant=grant, policy=cfg["policy_file"], provider="none",
                         project_root=broker.settings["project_root"], session_id=broker.settings["task_id"],
                         privacy_gate=PrivacyGate(consents=broker.consents, require_prepared=True))
        self.broker = broker
        profiles = cfg.get("profiles")
        if isinstance(profiles, dict) and profiles.get("enabled") is True:
            from .antigravity_hook import configured_provider
            from .profiles import resolve
            from .providers.safe import for_envelope
            context = self.envelope("", tool="http_request", arguments={
                "files": [route["source_file"] for route in broker.settings["routes"].values()]})
            provider = for_envelope(configured_provider(cfg), context)
            grant, _, _ = resolve(grant, profiles, session_id=broker.settings["task_id"],
                                  messages=[broker.task_request()], provider=provider)
            self.grant = grant

    def check_prepared(self, prepared: PreparedSend, *, consume_approval: bool = True):
        self.broker.ensure_current()
        return harness.check_prepared(prepared, consents=self.broker.consents, config=self.broker.config_path,
                                      consume_approval=consume_approval, recent=self.broker.recent_context())


class _SnapshotTransport:
    def __init__(self, broker: PreparedBroker, expiry: float) -> None:
        self.broker, self.expiry = broker, expiry

    def send(self, prepared: PreparedSend) -> int:
        self.broker.ensure_current()
        self.broker.task_request()
        if time.monotonic() >= self.expiry:
            raise TimeoutError("prepared snapshot expired before dispatch")
        return self.broker.sender.transport.send(prepared)


class PreparedBroker:
    def __init__(self, config_path: str) -> None:
        self.config_path = config_path
        self.config = harness.load_config(config_path)
        settings = self.config.get("prepared_sends")
        privacy = self.config.get("privacy_gate", {})
        if (not isinstance(settings, dict) or settings.get("enabled") is not True
                or self.config.get("mode") != "enforce" or privacy.get("enabled") is not True
                or privacy.get("require_prepared") is not True):
            raise ValueError("prepared execution requires enforce mode and the strict privacy profile")
        allowed = {"enabled", "task_id", "project_root", "client_file", "consent_store", "routes", "allow_loopback_http",
                   "snapshot_ttl_s", "max_snapshots", "development", "task_context"}
        if set(settings) - allowed:
            raise ValueError("unknown prepared harness setting")
        for key in ("task_id", "project_root", "client_file", "consent_store"):
            if not isinstance(settings.get(key), str) or not settings[key].strip():
                raise ValueError("prepared harness identity and protected paths are required")
        from .hookinput import session_id_problem
        if session_id_problem(settings["task_id"]):
            raise ValueError("invalid prepared task id")
        self.settings = settings
        self.ttl = settings.get("snapshot_ttl_s", 300)
        self.maximum = settings.get("max_snapshots", 16)
        if (isinstance(self.ttl, bool) or not isinstance(self.ttl, (float, int)) or not math.isfinite(self.ttl)
                or not 0 < self.ttl <= 3600 or type(self.maximum) is not int or not 1 <= self.maximum <= 64):
            raise ValueError("invalid prepared snapshot bounds")
        if not isinstance(settings.get("allow_loopback_http", False), bool):
            raise ValueError("invalid loopback setting")
        routes = settings.get("routes")
        if not isinstance(routes, dict) or not routes or len(routes) > 64:
            raise ValueError("prepared routes are required")
        from .sendclient import _NAME
        for name, route in routes.items():
            if (not isinstance(name, str) or not _NAME.fullmatch(name) or not isinstance(route, dict)
                    or set(route) != {"source_file", "destination", "method", "categories", "classification_complete", "contract"}
                    or not all(isinstance(route[k], str) and route[k] for k in ("source_file", "destination", "method"))
                    or not isinstance(route["categories"], list) or not isinstance(route["classification_complete"], bool)):
                raise ValueError("invalid prepared route")
            validate_categories(frozenset(route["categories"]))
            from .sendcontracts import validate
            validate(route["contract"])
        for key in ("client_file", "consent_store"):
            path = Path(settings[key]).expanduser().resolve()
            if ".semgate" not in {p.name.lower() for p in path.parents}:
                raise ValueError("prepared state must be under the protected .semgate tree")
        from .storepaths import operator_paths
        self.protected_paths = tuple(dict.fromkeys((self.config_path, self.config["grant_file"], self.config["policy_file"],
            settings["client_file"], settings["consent_store"], *(path for _, path in operator_paths(self.config)))))
        if "development" in settings:
            project = Path(settings["project_root"]).resolve()
            for name in self.protected_paths:
                lexical = Path(name).expanduser().absolute()
                # Both the configured alias and its target must be protected;
                # an agent-writable alias must not redirect an authority read.
                for path in (lexical, lexical.resolve()):
                    if path.is_relative_to(project):
                        parts = path.relative_to(project).parts
                        if not parts or parts[0] not in {".semgate", ".codex", ".agents"}:
                            raise ValueError("operator state must be outside the project or in its protected metadata trees")
        self.consents = ConsentStore(Path(settings["consent_store"]))
        self.signature = self._signature()
        self.sender = PreparedSender(_HarnessGate(self), self.consents, task_id=settings["task_id"],
                                     allow_loopback_http=settings.get("allow_loopback_http", False))
        self.lock = threading.Lock()
        self.recent_actions: list[dict] = []
        self.items: dict[str, tuple[PreparedSend, float]] = {}
        self.busy: set[str] = set()
        self.completed: dict[str, tuple[dict, float]] = {}
        self.development = None
        self.development_slot = threading.BoundedSemaphore(1)
        if "development" in settings:
            from .devworker import OfflineWorker
            self.development = OfflineWorker(settings["development"])

    def _signature(self) -> str:
        cfg = harness.load_config(self.config_path)
        return hashlib.sha256((canonical_json(cfg) + "\n" + Path(cfg["grant_file"]).read_text(encoding="utf-8")
                               + "\n" + Path(cfg["policy_file"]).read_text(encoding="utf-8")).encode()).hexdigest()

    def ensure_current(self) -> None:
        if self._signature() != self.signature:
            raise ValueError("prepared policy changed; restart the broker")

    def _prune(self) -> None:
        now = time.monotonic()
        self.items = {k: v for k, v in self.items.items() if v[1] > now}
        self.completed = {k: v for k, v in self.completed.items() if v[1] > now}

    @staticmethod
    def _outcome(decision) -> dict:
        evidence = decision.evidence.get("privacy", {})
        disposition = "deny" if decision.decision == "deny" else evidence.get("disposition", "needs_consent")
        if decision.decision != "allow" and disposition == "allow":
            disposition = "needs_inspection"
        return {"disposition": disposition, "reason_code": decision.reason_code, "delivery": "not_sent",
                **{k: evidence[k] for k in ("request_id", "grant_id") if evidence.get(k)},
                **({"approval_id": decision.evidence["approval_id"]} if decision.evidence.get("approval_id") else {})}

    def prepare(self, route_name: str) -> dict:
        self.ensure_current()
        self.task_request()
        route = self.settings["routes"].get(route_name)
        if route is None:
            raise ValueError("unknown prepared route")
        prepared = self.sender.prepare_file(Path(route["source_file"]), destination=route["destination"],
                    categories=frozenset(route["categories"]), classification_complete=route["classification_complete"],
                    method=route["method"])
        from .sendcontracts import canonicalize
        try:
            body = canonicalize(prepared.body, route["contract"])
        except (ValueError, UnicodeError):
            return {"disposition": "needs_inspection", "reason_code": "prepared_contract_mismatch", "delivery": "not_sent"}
        prepared = self.sender.prepare(body, destination=route["destination"], source=prepared.scope.source,
                    categories=prepared.categories, classification_complete=prepared.classification_complete,
                    method=route["method"], content_format=route["contract"]["format"])
        with self.lock:
            self._prune()
            if len(self.items) + len(self.busy) + len(self.completed) >= self.maximum:
                raise ValueError("prepared snapshot capacity reached")
            ident = secrets.token_hex(16)
            self.items[ident] = (prepared, time.monotonic() + self.ttl)
        decision = self.sender.gate.check_prepared(prepared, consume_approval=False)
        return dict(self._outcome(decision), prepared_id=ident, digest=prepared.digest)

    def dispatch(self, ident: str) -> dict:
        self.ensure_current()
        self.task_request()
        with self.lock:
            self._prune()
            if ident in self.completed or ident in self.busy or ident not in self.items:
                return {"disposition": "deny", "reason_code": "prepared_id_unavailable", "delivery": "not_sent"}
            prepared, expiry = self.items.pop(ident)
            self.busy.add(ident)
        result = {"disposition": "service_error", "reason_code": "prepared_dispatch_error", "delivery": "unknown"}
        try:
            sender = PreparedSender(self.sender.gate, self.consents, task_id=self.settings["task_id"],
                                    allow_loopback_http=self.settings.get("allow_loopback_http", False),
                                    transport=_SnapshotTransport(self, expiry))
            receipt = sender.send(prepared)
            result = {**receipt.outcome.record(), "delivery": receipt.delivery, "digest": receipt.digest}
            if receipt.approval_id:
                result["approval_id"] = receipt.approval_id
            if receipt.status is not None:
                result["status"] = receipt.status
            return dict(result, prepared_id=ident)
        finally:
            with self.lock:
                self.busy.remove(ident)
                if result["delivery"] == "not_sent" and result["disposition"] in {"needs_consent", "needs_inspection", "service_error"}:
                    self.items[ident] = (prepared, expiry)
                else:
                    self.completed[ident] = (result, expiry)

    def describe(self, ident: str) -> dict:
        self.ensure_current()
        with self.lock:
            self._prune()
            prepared, _ = self.items[ident]
        return {"prepared_id": ident, "scope": asdict(prepared.scope), "categories": sorted(prepared.categories),
                "digest": prepared.digest, "bytes": len(prepared.body)}

    def run_development(self, command: str) -> dict:
        return self._development(command=command)

    def write_development(self, arguments: dict) -> dict:
        from .devworker import validate_write
        return self._development(write=validate_write(arguments))

    def recent_context(self) -> list[dict]:
        """Last 20 observations from this broker; never user instructions."""
        from copy import deepcopy
        with self.lock:
            return deepcopy(self.recent_actions)

    def _remember_development(self, command: str | None, write: dict | None, decision: str, result: dict) -> None:
        output = "\n".join(str(result.get(key) or "")[:2900] for key in ("stdout", "stderr")).strip()
        summary = command if command is not None else "write " + write["path"]
        entry = {"tool": "bash" if command is not None else "write", "summary": summary[:500],
                 "decision": decision, "output": output,
                 "result": ("exit=" + str(result.get("exit_code", "unavailable"))
                            + "; timeout=" + str(bool(result.get("timed_out")))),
                 "files_changed": ([write["path"]] if write is not None and decision == "allow"
                                   and result.get("exit_code") == 0 and not result.get("timed_out") else [])}
        with self.lock:
            self.recent_actions.append(entry)
            self.recent_actions = self.recent_actions[-20:]

    def _development(self, *, command: str | None = None, write: dict | None = None) -> dict:
        self.ensure_current()
        self.task_request()
        if self.development is None:
            raise ValueError("offline development is not configured")
        if not self.development_slot.acquire(blocking=False):
            return {"disposition": "service_error", "reason_code": "development_busy", "delivery": "not_sent"}
        try:
            from .devworker import WriteConfinementError
            protected = self.protected_paths
            try:
                facts = self.development.verify(self.settings["project_root"], protected=protected)
                if command is not None:
                    from .cachecleanup import parse
                    if parse(command) is not None:
                        from dataclasses import replace
                        facts = replace(facts, cache_cleanup_command=command)
                    elif self.config.get("script_source") is True:
                        snapshot = self.development.inspect_script(self.settings["project_root"], command,
                            protected=protected, expected_facts=facts)
                        if snapshot is not None:
                            from . import rules
                            from .readonlyscript import network_probe_eligible
                            if rules.script_network_hit([snapshot.source]) and network_probe_eligible(snapshot.source):
                                from dataclasses import replace
                                facts = replace(facts, script_snapshot=snapshot)
                self.ensure_current()
                check = harness.check_local_write if write is not None else harness.check_development
                decision = check(write if write is not None else command, project=self.settings["project_root"],
                                                     task=self.settings["task_id"], config=self.config_path,
                                                     execution_facts=facts, recent=self.recent_context())
                if decision.decision != "allow":
                    self._remember_development(command, write, decision.decision, {})
                    return {"disposition": "deny" if decision.decision == "deny" else "needs_inspection",
                            "reason_code": decision.reason_code, "delivery": "not_sent",
                            **({"approval_id": decision.evidence["approval_id"]} if decision.evidence.get("approval_id") else {})}
                self.ensure_current()
                self.task_request()
                if self.sender.gate.grant.is_expired():
                    self._remember_development(command, write, "deny", {})
                    return {"disposition": "deny", "reason_code": "development_operator_grant_expired",
                            "delivery": "not_sent"}
                execute = self.development.write if write is not None else self.development.run
                try:
                    result = execute(self.settings["project_root"], write if write is not None else command,
                                     protected=protected, expected_facts=facts)
                except Exception:
                    self._remember_development(command, write, "unknown", {"stderr": "worker receipt unavailable"})
                    raise
                self._remember_development(command, write, "allow", result)
                return {"disposition": "allow", "reason_code": "development_offline", "delivery": "not_sent", **result}
            except WriteConfinementError as exc:
                # The project view cannot guarantee write confinement. Refuse
                # the effect; never fall back to another execution path.
                return {"disposition": "deny", "reason_code": exc.reason_code, "delivery": "not_sent",
                        "alias_audit": {"checked": exc.audit.get("checked", 0),
                                        "unverifiable": exc.audit.get("unverifiable", 0),
                                        "offenders": [path for item in exc.audit.get("offenders", [])
                                                      for path in item.get("paths", [])]}}
        finally:
            self.development_slot.release()

    def task_request(self) -> str:
        from .taskcontext import request_for
        return request_for(self.config, task=self.settings["task_id"], project=self.settings["project_root"])

    def consent(self, request: dict) -> dict:
        self.ensure_current()
        action, ident = request["action"], request["request_id"]
        auth = Auth("operator_api")
        if action == "approve":
            self.consents.approve(ident, auth=auth, task_scope=request.get("task_scope", True), ttl_s=request.get("ttl_s"))
        elif action == "revoke":
            self.consents.revoke(ident, auth=auth)
        elif action == "close-task":
            self.consents.close_task_of(ident, auth=auth)
        else:
            raise ValueError("invalid consent action")
        return {"request_id": ident, "action": action}

    def close(self) -> None:
        with self.lock:
            self.recent_actions.clear()
        if self.development is not None:
            self.development.close()
