"""`semgate serve --http`: the harness API (semgate.harness) over HTTP.

    POST /v1/check     body: semgate-check/1 (semgate/data/check_request.schema.json)
                       200: semgate-decision/1 {decision: allow|ask|deny, reason, reason_code, stage,
                            judgment_id, approval_id (with ask), timeout (when the deadline passed)}
    POST /v1/approve   body: semgate-approve/1 {approval_id, approved, by, note?}   HUMAN SIDE ONLY
                       200: {approval_id, status, expires_at}; 404 unknown/expired id; 409 already answered/used
    GET  /v1/health    200: {ok, service, version, request_schema, response_schema, workers, stuck}

    Opt-in prepared execution (docs/guide.md, "Prepared execution in the HTTP harness"):
    POST /v1/send/prepare   agent: {route}; immutable server-side snapshot + typed outcome
    POST /v1/send/dispatch  agent: {prepared_id}; recheck + send once + delivery receipt
    POST /v1/send/run       agent: {command}; ordinary permission check + offline development worker
    POST /v1/send/describe  operator: {prepared_id}; scope/digest/categories, no body
    POST /v1/send/consent   operator: {action: approve|revoke|close-task, request_id, task_scope?, ttl_s?}
    These endpoints require distinct agent/operator tokens. Dispatch is synchronous
    and never enters the abandonable judgment worker pool described below.

Workers and deadlines are serve.Server's (the `semgate serve --stdio`
pool): a bounded pool of judge threads (`serve.workers`, default 4), a
deadline per request (`serve.budget_ms` minus `serve.margin_ms`, or the
request's timeout_ms), "ask" at the deadline, never "allow". When every
worker is held by a judgment past its deadline, the pool is replaced by a
new one (the stuck threads cannot be stopped); when too many stuck threads
add up, checks are answered 503 + ask until they finish.

Security defaults:
  - binds 127.0.0.1. A non-loopback --host needs --allow-remote AND
    --token-file (no TLS here: put a TLS proxy in front for remote use).
  - bearer tokens: --token-file guards /v1/check; /v1/approve needs
    --approve-token-file (a separate human-side token) or, without it, the
    --token-file token. No token at all: /v1/approve is refused (403), so
    the agent side can never approve its own call through an open port.
    Tokens are compared in constant time and never logged.
  - no CORS: a request with an Origin header (a browser page) is refused
    (403), OPTIONS is 405 without CORS headers, and on loopback the Host
    header must be a loopback name (DNS rebinding).
  - JSON only (Content-Type application/json), Content-Length required, body
    at most hook_max_payload_bytes (semgate.hookinput; 413 above it, not
    read), 30 s to send it, a bounded number of open connections (503).
  - fail closed: every /v1/check answer, error answers included, carries
    decision "ask" unless the pipeline decided allow or deny.
  - answers are masked (harness.public_text: secret values, the home folder);
    internal exception messages go to stderr, not to the caller.
"""
from __future__ import annotations

import argparse
import hmac
import ipaddress
import itertools
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

from . import harness, hookinput
from .serve import DEFAULT_BUDGET_MS, DEFAULT_MARGIN_MS, DEFAULT_WORKERS, Server, _settings

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8787
DEFAULT_MAX_CONNECTIONS = 64
READ_TIMEOUT_S = 30
TOKEN_MIN_CHARS = 16
LOOPBACK_NAMES = frozenset({"localhost", "127.0.0.1", "::1"})


def is_loopback(host: str) -> bool:
    h = str(host or "").strip().strip("[]").lower()
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def read_token(path: str) -> str:
    """The token in `path` (whitespace around it removed). Raises ValueError
    when it is shorter than TOKEN_MIN_CHARS or holds whitespace."""
    with open(os.path.expanduser(path), encoding="utf-8") as handle:
        token = handle.read().strip()
    if len(token) < TOKEN_MIN_CHARS or any(c.isspace() for c in token):
        raise ValueError(f"the token in {path} must be at least {TOKEN_MIN_CHARS} characters without spaces")
    if os.name == "posix":
        try:
            if os.stat(os.path.expanduser(path)).st_mode & 0o077:
                print(f"semgate serve: WARNING: {path} can be read by other users (chmod 600 it)", file=sys.stderr)
        except OSError:
            pass
    return token


class _Waiter:
    __slots__ = ("event", "value")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.value: Optional[Dict[str, Any]] = None


class _Router:
    """serve.Server's stdout: each answer line goes to the HTTP thread that waits for its id."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.waiting: Dict[int, _Waiter] = {}

    def register(self, rid: int) -> _Waiter:
        w = _Waiter()
        with self.lock:
            self.waiting[rid] = w
        return w

    def forget(self, rid: int) -> None:
        with self.lock:
            self.waiting.pop(rid, None)

    def write(self, text: str) -> None:
        for line in str(text).splitlines():
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            with self.lock:
                w = self.waiting.pop(obj.get("id"), None) if isinstance(obj, dict) else None
            if w is not None:
                w.value = obj
                w.event.set()

    def flush(self) -> None:
        pass


class _Pool(Server):
    """serve.Server without the stdio exit on an idle stuck judgment: an HTTP
    server keeps serving with the other workers (the pool is replaced only
    when every worker is stuck, see HttpGate._recycle)."""

    def _maybe_restart_when_idle(self) -> None:
        return


class HttpGate:
    """The request logic, without sockets (tests call it directly too)."""

    def __init__(self, config_path: str, *, check_token: str = "", approve_token: str = "",
                 settings: Optional[Tuple[int, int, int]] = None, max_stuck: int = 0) -> None:
        self.config_path = config_path
        self.check_token = check_token
        self.approve_token = approve_token
        if settings is None:
            try:
                from .antigravity_hook import load_json
                settings = _settings(load_json(config_path))
            except Exception:
                settings = (DEFAULT_WORKERS, DEFAULT_BUDGET_MS, DEFAULT_MARGIN_MS)
        self.workers, self.budget_ms, self.margin_ms = settings
        self.max_stuck = max_stuck or 4 * self.workers
        self.limit = hookinput.max_payload_bytes(config_path)
        self.router = _Router()
        self.ids = itertools.count(1)
        self.lock = threading.Lock()
        self.retired: List[Server] = []
        self.recycles = 0
        self.pool = self._new_pool()
        self.prepared = None
        self.prepared_lock = threading.Lock()

    # ---------- pool ----------
    def _new_pool(self) -> Server:
        return _Pool(self.config_path, self.router, workers=self.workers, budget_ms=self.budget_ms,
                     margin_ms=self.margin_ms, on_restart=self._recycle, judge_fn=self._judge)

    def _recycle(self, why: str) -> None:
        with self.lock:
            old = self.pool
            self.retired.append(old)
            self.pool = self._new_pool()
            self.recycles += 1
        print(f"semgate serve --http: new worker pool ({why})", file=sys.stderr)
        old.close()

    def stuck(self) -> int:
        with self.lock:
            self.retired = [p for p in self.retired if p.stuck > 0]
            return sum(p.stuck for p in self.retired) + self.pool.stuck

    @staticmethod
    def _judge(host: str, request: Dict[str, Any], config: Any, meta: Optional[Dict[str, Any]] = None,
               line_bytes: int = 0) -> Dict[str, Any]:
        try:
            return harness.judge_check(request["check"], config, meta, line_bytes)
        except Exception as exc:
            hookinput.note_rejection(config, exc, harness.HOST)
            print(f"semgate serve --http: check failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return harness.fail_answer("semgate failure; asking human: " + harness.failure_text(exc))

    # ---------- auth ----------
    @staticmethod
    def _bearer(header: Optional[str]) -> str:
        if not header:
            return ""
        scheme, _, value = header.partition(" ")
        return value.strip() if scheme.lower() == "bearer" else ""

    def check_allowed(self, authorization: Optional[str]) -> bool:
        if not self.check_token:
            return True
        return hmac.compare_digest(self._bearer(authorization).encode(), self.check_token.encode())

    def approve_allowed(self, authorization: Optional[str]) -> Tuple[bool, str]:
        token = self.approve_token or self.check_token
        if not token:
            return False, "approvals need a token: start semgate serve with --approve-token-file (or --token-file)"
        if hmac.compare_digest(self._bearer(authorization).encode(), token.encode()):
            return True, ""
        return False, "missing or wrong bearer token for approvals"

    def prepared_allowed(self, authorization: Optional[str], *, operator: bool) -> bool:
        # No legacy shared-token fallback for disclosure authority.
        if not self.check_token or not self.approve_token or hmac.compare_digest(self.check_token.encode(), self.approve_token.encode()):
            return False
        expected = self.approve_token if operator else self.check_token
        return hmac.compare_digest(self._bearer(authorization).encode(), expected.encode())

    def prepared_action(self, action: str, body: bytes) -> Tuple[int, Dict[str, Any]]:
        """Synchronous execution path; never enters the abandonable judgment pool."""
        try:
            if len(body) > (32768 if action == "write" else 24576 if action == "run" else 4096):
                raise ValueError("prepared request limit")
            request = json.loads(body)
            from .sendclient import _ID, _NAME
            if not isinstance(request, dict):
                raise ValueError("prepared request must be an object")
            if action == "write":
                from .devworker import validate_write
                request = validate_write(request)
            elif action == "run":
                from .devworker import MAX_COMMAND
                if (set(request) != {"command"} or not isinstance(request["command"], str)
                        or not request["command"].strip() or len(request["command"]) > MAX_COMMAND or "\0" in request["command"]):
                    raise ValueError("invalid development command")
            elif action == "prepare":
                if set(request) != {"route"} or not isinstance(request["route"], str) or not _NAME.fullmatch(request["route"]):
                    raise ValueError("invalid prepared route")
            elif action in {"dispatch", "describe"}:
                if set(request) != {"prepared_id"} or not isinstance(request["prepared_id"], str) or not _ID.fullmatch(request["prepared_id"]):
                    raise ValueError("invalid prepared id")
            elif action == "consent":
                if (set(request) - {"action", "request_id", "task_scope", "ttl_s"} or not {"action", "request_id"} <= set(request)
                        or request["action"] not in {"approve", "revoke", "close-task"}
                        or not isinstance(request["request_id"], str) or not _ID.fullmatch(request["request_id"])):
                    raise ValueError("invalid consent request")
            else:
                raise ValueError("unknown prepared action")
            from .sendharness import PreparedBroker
            with self.prepared_lock:
                if self.prepared is None:
                    self.prepared = PreparedBroker(self.config_path)
                broker = self.prepared
            if action == "run":
                result = broker.run_development(request["command"])
            elif action == "write":
                result = broker.write_development(request)
            elif action == "prepare":
                result = broker.prepare(request["route"])
            elif action == "dispatch":
                result = broker.dispatch(request["prepared_id"])
            elif action == "describe":
                result = broker.describe(request["prepared_id"])
            else:
                result = broker.consent(request)
            return 200, result
        except Exception:
            # Do not log bodies, credentials, scope text or raw exceptions.
            return 503, {"disposition": "service_error", "reason_code": "prepared_harness_error",
                         "delivery": "unknown" if action == "dispatch" else "not_sent"}

    # ---------- endpoints ----------
    def health(self) -> Dict[str, Any]:
        from . import __version__
        stuck = self.stuck()
        return {"ok": stuck < self.max_stuck, "service": "semgate", "version": __version__,
                "request_schema": harness.REQUEST_SCHEMA, "response_schema": harness.RESPONSE_SCHEMA,
                "workers": self.workers, "stuck": stuck}

    def reject(self, exc: Exception) -> Dict[str, Any]:
        """A request that is not judged: ledger incident (hook_input_rejected), ask."""
        hookinput.note_rejection(self._config_or_path(), exc, harness.HOST)
        return harness.fail_answer("semgate failure; asking human: " + harness.failure_text(exc))

    def _config_or_path(self) -> Any:
        try:
            return harness.load_config(self.config_path)
        except Exception:
            return self.config_path

    def check(self, body: bytes) -> Tuple[int, Dict[str, Any]]:
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            return 400, self.reject(hookinput.InputRejected(f"the body is not valid JSON ({exc})"[:300], "payload_not_json",
                                                            {"bytes": len(body)}))
        try:
            req = harness.validate_request(parsed)
        except harness.RequestError as exc:
            return 400, self.reject(exc)
        if self.stuck() >= self.max_stuck:
            return 503, harness.fail_answer("semgate is overloaded: judgments passed their deadline and still run; "
                                            "asking human")
        rid = next(self.ids)
        waiter = self.router.register(rid)
        budget = int(req.get("timeout_ms") or self.budget_ms)
        msg = {"id": rid, "host": harness.HOST, "timeout_ms": budget,
               # sessionID / callID: what serve.Server records in host_response.
               "request": {"sessionID": req["session_id"], "callID": req.get("call_id"), "check": req}}
        with self.lock:
            pool = self.pool
        pool.submit(json.dumps(msg), len(body))
        if not waiter.event.wait(timeout=budget / 1000.0 + 5.0):
            self.router.forget(rid)
            return 200, harness.fail_answer("semgate did not decide in time; asking human", timeout=True)
        return 200, self._shape(waiter.value or {})

    @staticmethod
    def _shape(obj: Dict[str, Any]) -> Dict[str, Any]:
        decision = obj.get("decision") if obj.get("decision") in ("allow", "ask", "deny") else "ask"
        timeout = bool(obj.get("timeout"))
        out: Dict[str, Any] = {"schema": harness.RESPONSE_SCHEMA, "decision": decision,
                               "reason": harness.public_text(obj.get("reason", ""))[:1000],
                               "reason_code": str(obj.get("reason_code") or
                                                  ("semgate_timeout" if timeout else "semgate_failure")),
                               "stage": str(obj.get("stage") or ""), "judgment_id": str(obj.get("judgment_id") or "")}
        if obj.get("approval_id"):
            out["approval_id"] = str(obj["approval_id"])
        if timeout:
            out["timeout"] = True
        return out

    def approve(self, body: bytes) -> Tuple[int, Dict[str, Any]]:
        from . import approvals, filelock
        try:
            parsed = json.loads(body.decode("utf-8"))
            req = harness.validate_approve(parsed)
            return 200, harness.approve(req["approval_id"], req["approved"], req["by"], note=req["note"],
                                        config=self.config_path)
        except (UnicodeDecodeError, ValueError) as exc:
            if isinstance(exc, approvals.ApprovalError):
                status = {"not_found": 404, "conflict": 409}.get(exc.code, 400)
                return status, {"error": harness.public_text(exc)}
            if isinstance(exc, harness.RequestError):
                return 400, {"error": harness.public_text(exc)}
            return 400, {"error": "the body is not valid JSON"}
        except filelock.LockTimeout:
            return 503, {"error": "the approval store is busy; try again"}
        except Exception as exc:
            print(f"semgate serve --http: approve failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 500, {"error": f"semgate failure: {harness.failure_text(exc)}"}

    def close(self) -> None:
        try:
            if self.prepared is not None:
                self.prepared.close()
        finally:
            with self.lock:
                pools = [self.pool] + self.retired
            for p in pools:
                try:
                    p.close()
                except Exception:
                    pass


def _handler_class(gate: HttpGate, allow_remote: bool) -> type:
    class Handler(BaseHTTPRequestHandler):
        server_version = "semgate"
        sys_version = ""
        timeout = READ_TIMEOUT_S

        def log_message(self, fmt: str, *args: Any) -> None:     # no headers, no bodies, no tokens
            sys.stderr.write("semgate serve --http: %s %s\n" % (self.address_string(), fmt % args))

        # ---------- replies ----------
        def _send(self, status: int, obj: Dict[str, Any], extra: Optional[Dict[str, str]] = None) -> None:
            data = (json.dumps(obj, sort_keys=True) + "\n").encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _discard_body(self) -> None:
            """Read and drop a body we will not use (bounded by the size
            limit), so the reply is not lost to a TCP reset: closing a socket
            with unread bytes resets the connection on Windows."""
            if self.headers.get("Transfer-Encoding"):
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                return
            if 0 < length <= gate.limit:
                try:
                    while length > 0:
                        chunk = self.rfile.read(min(length, 1 << 16))
                        if not chunk:
                            break
                        length -= len(chunk)
                except (socket.timeout, OSError):
                    pass

        def _refuse(self, status: int, message: str, check: bool, extra: Optional[Dict[str, str]] = None,
                    drain: bool = True) -> None:
            if drain:
                self._discard_body()
            body: Dict[str, Any] = {"error": message}
            if check:
                body = dict(harness.fail_answer("semgate refused the request; asking human: " + message), error=message)
            self.close_connection = True
            self._send(status, body, extra)

        # ---------- checks every request passes ----------
        def _origin_and_host_ok(self, check: bool) -> bool:
            if self.headers.get("Origin") is not None:
                self._refuse(403, "requests from a browser page (Origin header) are refused", check)
                return False
            if not allow_remote:
                host = self.headers.get("Host")
                if host is not None:
                    name = host.strip()
                    if name.startswith("["):
                        name = name[1:].split("]", 1)[0]
                    elif name.count(":") == 1:
                        name = name.split(":", 1)[0]
                    if name.lower() not in LOOPBACK_NAMES:
                        self._refuse(403, "the Host header is not a loopback name", check)
                        return False
            return True

        def _body(self, check: bool) -> Optional[bytes]:
            ctype = (self.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            if ctype != "application/json":
                self._refuse(415, "Content-Type must be application/json", check)
                return None
            if self.headers.get("Transfer-Encoding"):
                self._refuse(411, "send the body with Content-Length (no chunked transfer)", check, drain=False)
                return None
            raw = self.headers.get("Content-Length")
            if raw is None:
                self._refuse(411, "Content-Length is required", check, drain=False)
                return None
            try:
                length = int(raw)
                if length < 0:
                    raise ValueError
            except ValueError:
                self._refuse(400, "Content-Length is not a number", check, drain=False)
                return None
            if length > gate.limit:
                exc = hookinput.InputRejected(
                    f"request body is {length} bytes, above hook_max_payload_bytes ({gate.limit}); not read",
                    "payload_over_limit", {"bytes": length, "limit": gate.limit})
                hookinput.note_rejection(gate._config_or_path(), exc, harness.HOST)
                self._refuse(413, str(exc), check, drain=False)
                return None
            try:
                data = self.rfile.read(length)
            except (socket.timeout, OSError):
                self.close_connection = True
                return None
            if len(data) != length:
                self._refuse(400, "the body is shorter than Content-Length", check, drain=False)
                return None
            return data

        # ---------- methods ----------
        def do_GET(self) -> None:
            if not self._origin_and_host_ok(False):
                return
            if self.path.split("?", 1)[0] == "/v1/health":
                health = gate.health()
                self._send(200 if health["ok"] else 503, health)
                return
            self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            send_actions = {"/v1/send/" + name: name for name in ("prepare", "dispatch", "describe", "consent", "run", "write")}
            if path not in ("/v1/check", "/v1/approve") and path not in send_actions:
                self._send(404, {"error": "not found"})
                return
            is_check = path == "/v1/check"
            if not self._origin_and_host_ok(is_check):
                return
            auth = self.headers.get("Authorization")
            if path in send_actions:
                if not gate.prepared_allowed(auth, operator=send_actions[path] in {"describe", "consent"}):
                    self._refuse(403, "prepared sends require separate agent and operator tokens", False)
                    return
            elif is_check:
                if not gate.check_allowed(auth):
                    self._refuse(401, "missing or wrong bearer token", True, {"WWW-Authenticate": "Bearer"})
                    return
            else:
                ok, why = gate.approve_allowed(auth)
                if not ok:
                    configured = bool(gate.approve_token or gate.check_token)
                    self._refuse(401 if configured else 403, why, False,
                                 {"WWW-Authenticate": "Bearer"} if configured else None)
                    return
            body = self._body(is_check)
            if body is None:
                return
            if path in send_actions:
                status, obj = gate.prepared_action(send_actions[path], body)
            else:
                status, obj = gate.check(body) if is_check else gate.approve(body)
            self._send(status, obj)

        def _not_allowed(self) -> None:
            self._send(405, {"error": "method not allowed"}, {"Allow": "GET, POST"})

        do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _not_allowed    # no CORS preflight answer

    return Handler


class _HTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, addr: Tuple[str, int], handler: type, max_connections: int) -> None:
        self.slots = threading.BoundedSemaphore(max(1, int(max_connections)))
        super().__init__(addr, handler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self.slots.acquire(blocking=False):
            body = json.dumps(harness.fail_answer("semgate has too many open connections; asking human")).encode()
            try:                           # read what the client already sent (no reset on close)
                request.settimeout(0.5)
                request.recv(1 << 16)
            except OSError:
                pass
            try:
                request.sendall(b"HTTP/1.0 503 Service Unavailable\r\nContent-Type: application/json\r\n"
                                b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class _HTTPServer6(_HTTPServer):
    address_family = socket.AF_INET6


def make_server(config_path: str, *, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, check_token: str = "",
                approve_token: str = "", allow_remote: bool = False,
                max_connections: int = DEFAULT_MAX_CONNECTIONS,
                settings: Optional[Tuple[int, int, int]] = None) -> Tuple[_HTTPServer, HttpGate]:
    """Bind (port 0: any free port) and return (server, gate); call
    server.serve_forever(). Raises ValueError for an unsafe setup."""
    if not is_loopback(host):
        if not allow_remote:
            raise ValueError(f"{host} is not a loopback address; add --allow-remote (and --token-file) to listen there")
        if not check_token:
            raise ValueError("--allow-remote needs --token-file: a remote /v1/check must carry a token")
    if check_token and approve_token and hmac.compare_digest(check_token.encode(), approve_token.encode()):
        raise ValueError("the approve token must differ from the check token (the agent side holds the check token)")
    gate = HttpGate(config_path, check_token=check_token, approve_token=approve_token, settings=settings)
    cls = _HTTPServer6 if ":" in host.strip("[]") else _HTTPServer
    server = cls((host.strip("[]"), int(port)), _handler_class(gate, allow_remote), max_connections)
    return server, gate


def main(args: argparse.Namespace) -> int:
    try:
        check_token = read_token(args.token_file) if args.token_file else ""
        approve_token = read_token(args.approve_token_file) if args.approve_token_file else ""
        server, gate = make_server(args.config, host=args.host, port=args.port, check_token=check_token,
                                   approve_token=approve_token, allow_remote=args.allow_remote,
                                   max_connections=args.max_connections)
    except (OSError, ValueError) as exc:
        print(f"semgate serve --http: {exc}", file=sys.stderr)
        return 2
    host, port = server.server_address[:2]
    shown = f"[{host}]" if ":" in str(host) else str(host)
    approvals = ("separate approve token" if approve_token else "the check token" if check_token else
                 "OFF (no token: /v1/approve answers 403)")
    print(f"semgate serve --http: listening on http://{shown}:{port}  config {args.config}  "
          f"check token: {'on' if check_token else 'off'}  approvals: {approvals}", file=sys.stderr)
    if not is_loopback(str(host)):
        print("semgate serve --http: WARNING: listening beyond this machine without TLS; put a TLS proxy in front",
              file=sys.stderr)
    if args.port_file:
        with open(args.port_file, "w", encoding="utf-8") as handle:
            handle.write(f"{port}\n")
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        gate.close()
    return 0


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host", default=DEFAULT_HOST, help="address to listen on (default 127.0.0.1; a non-loopback "
                                                             "address needs --allow-remote and --token-file)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port (default {DEFAULT_PORT}; 0 = any free port)")
    parser.add_argument("--token-file", default="", help="file with the bearer token for /v1/check (and for "
                                                         "/v1/approve when --approve-token-file is not given)")
    parser.add_argument("--approve-token-file", default="", help="file with a separate bearer token for /v1/approve "
                                                                 "(the human side); without any token /v1/approve is off")
    parser.add_argument("--allow-remote", action="store_true", help="allow a non-loopback --host (needs --token-file)")
    parser.add_argument("--max-connections", type=int, default=DEFAULT_MAX_CONNECTIONS,
                        help=f"open connections at once (default {DEFAULT_MAX_CONNECTIONS}); more get 503")
    parser.add_argument("--port-file", default="", help="write the port here once listening (useful with --port 0)")


def wait_for_port_file(path: str, timeout: float = 20.0) -> int:
    """Test/launcher helper: the port a `--port-file` server wrote."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with open(path, encoding="utf-8") as handle:
                text = handle.read().strip()
            if text:
                return int(text)
        except (OSError, ValueError):
            pass
        time.sleep(0.05)
    raise TimeoutError(f"no port in {path} after {timeout} s")
