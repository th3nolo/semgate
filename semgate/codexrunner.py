"""Codex without ambient execution authority; Semgate owns the effectful tools.

The 0.153.1 app-server contract is pinned deliberately. An empty environment
selection removes native shell/file executors, including calls invented by a
model. The only effectful callbacks are validated here and sent to the prepared
broker. Advisory hooks are never the execution boundary.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import tempfile
import threading
import time

from . import proc, sendclient

VERSION = "0.153.1"
DISABLED_FEATURES = ("shell_tool", "multi_agent", "multi_agent_v2", "apps", "remote_plugin", "skill_search",
                     "code_mode", "code_mode_host", "js_repl", "memories", "shell_snapshot", "tool_suggest", "remote_control")
TOOLS = {
    "semgate_run": ("run", "command", "Run a Linux development command in the offline workspace. Use this for reads, edits, tests and builds."),
    "semgate_write": ("write", None, "Replace a project file with literal UTF-8 content (up to 4096 bytes) in the offline worker, after the ordinary permission check. Parent directories must exist. Content is data and is never executed."),
    "semgate_prepare": ("prepare", "route", "Prepare an immutable upload from an operator-configured route; request consent if needed."),
    "semgate_dispatch": ("dispatch", "prepared_id", "Send an existing prepared snapshot. The broker rechecks current task consent."),
}


def tool_specs():
    return [{"type": "function", "name": name, "description": description,
             "inputSchema": {"type": "object", "properties": {k: {"type": "string"} for k in ([key] if key else ["path", "content"])},
                             "required": [key] if key else ["path", "content"], "additionalProperties": False}}
            for name, (_, key, description) in TOOLS.items()]


def execute_tool(connection: Path, name: str, arguments, *, namespace=None):
    """Final allowlist. Never execute model arguments in this host process."""
    try:
        if namespace is not None or name not in TOOLS:
            raise ValueError("unknown tool")
        action, key, _ = TOOLS[name]
        if action == "write":
            from .devworker import validate_write
            return sendclient.request(connection, action, validate_write(arguments))
        if not isinstance(arguments, dict) or set(arguments) != {key}:
            raise ValueError("invalid tool fields")
        target = arguments[key]
        if not isinstance(target, str):
            raise ValueError("invalid tool value")
        if action == "run":
            if not target.strip() or len(target) > 4096 or "\0" in target:
                raise ValueError("invalid command")
        elif not (sendclient._NAME if action == "prepare" else sendclient._ID).fullmatch(target):
            raise ValueError("invalid identifier")
        return sendclient.request(connection, action, target)
    except Exception:
        # A broken hook, client or broker never selects a local fallback.
        return {"disposition": "service_error", "reason_code": "guarded_executor_error",
                "delivery": "unknown" if name == "semgate_dispatch" else "not_sent"}


def create_home(parent: Path, *, model: str, base_url: str, env_key: str, hooks=None, auth_file=None):
    """Fresh operator-owned runtime; no project or personal MCP/plugin config."""
    from urllib.parse import urlsplit
    import ipaddress
    parts = urlsplit(base_url)
    if parts.username or parts.password or parts.query or parts.fragment or not parts.hostname:
        raise ValueError("invalid model provider URL")
    if parts.scheme != "https" and not (parts.scheme == "http" and ipaddress.ip_address(parts.hostname).is_loopback):
        raise ValueError("model provider requires HTTPS or literal loopback HTTP")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", env_key) or not model or len(model) > 128:
        raise ValueError("invalid model configuration")
    home = Path(tempfile.mkdtemp(prefix="codex-guarded-", dir=parent))
    lines = [f"model = {json.dumps(model)}", 'model_provider = "semgate"',
             'check_for_update_on_startup = false', 'web_search = "disabled"',
             '[model_providers.semgate]', 'name = "operator-selected model"',
             f"base_url = {json.dumps(base_url)}", f"env_key = {json.dumps(env_key)}", 'wire_api = "responses"',
             '[skills]', 'include_instructions = false', '[features]']
    for name in DISABLED_FEATURES:
        lines.append(name + " = false")
    (home / "config.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (home / "semgate-runtime.json").write_text(json.dumps({"env_key": env_key}), encoding="utf-8")
    if hooks is not None:
        (home / "hooks.json").write_text(json.dumps(hooks), encoding="utf-8")
    if auth_file is not None:
        (home / "auth.json").write_bytes(Path(auth_file).read_bytes())
    return home


def validate_runtime(config):
    """Reject ambient executors introduced by a managed/system config layer."""
    features = config.get("features", {})
    if (config.get("mcp_servers") or config.get("plugins") or config.get("web_search") != "disabled"
            or any(features.get(name) is not False for name in DISABLED_FEATURES)):
        raise ValueError("guarded Codex runtime has ambient capabilities")


class CodexRunner:
    def __init__(self, binary: Path, home: Path, connection: Path, *, timeout_s=900, env=None, event=None):
        self.binary, self.home, self.connection = binary.resolve(), home.resolve(), connection.resolve()
        self.timeout = timeout_s
        if type(timeout_s) is not int or not 1 <= timeout_s <= 86400:
            raise ValueError("invalid agent deadline")
        parent_env = env if env is not None else os.environ
        self.env = {key: value for key, value in parent_env.items() if key.upper() in {
            "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "SYSTEMDRIVE", "LANG", "LC_ALL",
            "USER", "LOGNAME"}}
        # Only the configured model key is inherited, never the full host secret set.
        # create_home writes this small operator-owned marker separately from TOML.
        marker = self.home / "semgate-runtime.json"
        if marker.is_file():
            key = json.loads(marker.read_text())["env_key"]
            if key in parent_env:
                self.env[key] = parent_env[key]
        else:
            raise ValueError("guarded Codex requires a fresh Semgate runtime")
        for key in ("CODEX_HOME", "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "TEMP", "TMP"):
            self.env[key] = str(self.home)
        self.event = event or (lambda _: None)
        self.process = None
        self.inbox = queue.Queue(maxsize=256)
        self.sequence = 0
        self.thread_id = None
        self.seen = set()

    def _write(self, value):
        self.process.stdin.write((json.dumps(value) + "\n").encode())
        self.process.stdin.flush()

    def _request(self, method, params):
        self.sequence += 1
        self._write({"id": self.sequence, "method": method, "params": params})
        return self.sequence

    def _next(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("guarded agent deadline")
        try:
            message = self.inbox.get(timeout=remaining)
        except queue.Empty:
            raise TimeoutError("guarded agent deadline") from None
        if not isinstance(message, dict):
            raise RuntimeError("app-server protocol closed or invalid")
        if "method" in message:
            self.event(message)
        return message

    def _reply(self, message):
        params = message.get("params", {})
        if (message["method"] == "item/tool/call" and params.get("threadId") == self.thread_id
                and isinstance(params.get("callId"), str) and params["callId"] not in self.seen):
            self.seen.add(params["callId"])
            if time.monotonic() >= self.deadline:
                raise TimeoutError("guarded agent deadline before effect")
            value = execute_tool(self.connection, params.get("tool"), params.get("arguments"), namespace=params.get("namespace"))
            self.event({"method": "semgate/receipt", "params": {"tool": params.get("tool"),
                        "arguments": params.get("arguments"), "receipt": value}})
            self._write({"id": message["id"], "result": {"contentItems": [{"type": "inputText", "text": json.dumps(value)}],
                "success": value.get("disposition") not in {"service_error", "deny"}}})
        else:
            # Includes native execution/permission requests. No automatic approval.
            self._write({"id": message["id"], "error": {"code": -32601, "message": "Guarded harness rejects this request"}})

    def _wait(self, ident):
        while True:
            message = self._next()
            if "method" in message and "id" in message:
                self._reply(message)
            elif message.get("id") == ident:
                if "error" in message:
                    raise RuntimeError("app-server rejected guarded configuration")
                return message["result"]

    def run(self, prompt):
        version = proc.run([str(self.binary), "--version"], capture_output=True, text=True, check=True, timeout=10).stdout.strip()
        if version != "codex-cli " + VERSION:
            raise ValueError("guarded Codex requires the validated app-server version " + VERSION)
        self.deadline = time.monotonic() + self.timeout
        # Start outside the project. Never load its .codex overrides or executors.
        with tempfile.TemporaryFile() as errors:
            self.process = proc.popen([str(self.binary), "app-server", "--stdio"], cwd=self.home, env=self.env,
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
            def read():
                try:
                    while line := self.process.stdout.readline(1048577):
                        if len(line) > 1048576:
                            break
                        self.inbox.put(json.loads(line))
                except (ValueError, OSError):
                    pass
                finally:
                    self.inbox.put(None)
            reader = threading.Thread(target=read, daemon=True)
            reader.start()
            try:
                self._wait(self._request("initialize", {"clientInfo": {"name": "semgate", "version": "0.4.3"},
                            "capabilities": {"experimentalApi": True}}))
                self._write({"method": "initialized"})
                effective = self._wait(self._request("config/read", {"includeLayers": False}))
                validate_runtime(effective["config"])
                thread = self._wait(self._request("thread/start", {"cwd": str(self.home), "environments": [],
                    "approvalPolicy": "never", "sandbox": "read-only", "ephemeral": True, "dynamicTools": tool_specs(),
                    "developerInstructions": "Use semgate_run for workspace reads, tests and builds in /workspace; "
                    "use semgate_write for small literal file replacements. "
                    "Use semgate_prepare and semgate_dispatch for uploads. Only the human operator can approve or revoke consent."}))
                self.thread_id = thread["thread"]["id"]
                self._wait(self._request("turn/start", {"threadId": self.thread_id, "environments": [],
                    "input": [{"type": "text", "text": prompt}]}))
                while True:
                    message = self._next()
                    if "method" in message and "id" in message:
                        self._reply(message)
                    elif message.get("method") == "turn/completed" and message["params"].get("threadId") == self.thread_id:
                        turn = message["params"]["turn"]
                        if turn["status"] != "completed":
                            raise RuntimeError("guarded agent turn did not complete")
                        return {"boundary": "semgate-owned-tools/1", "codex_version": VERSION, "status": "completed",
                                "configured_model": effective["config"].get("model"),
                                "configured_provider": effective["config"].get("model_provider")}
            finally:
                self.process.stdin.close()
                if self.process.poll() is None:
                    self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5)
                self.process.stdout.close()
                reader.join(2)


def main(argv=None, *, event=None, env=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path, help="operator Semgate config with prepared_sends + development")
    parser.add_argument("--codex-bin", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path, help="existing operator-owned directory outside the project")
    parser.add_argument("--model", required=True)
    parser.add_argument("--base-url", required=True, help="operator-approved Responses API provider, including /v1")
    parser.add_argument("--env-key", required=True)
    parser.add_argument("--timeout-s", type=int, default=900)
    parser.add_argument("prompt")
    args = parser.parse_args(argv)
    from .harness import load_config
    cfg = load_config(args.config)
    settings = cfg.get("prepared_sends", {})
    project, state = Path(settings["project_root"]).resolve(), args.state_dir.resolve(strict=True)
    if state.is_relative_to(project) or Path(__file__).resolve().is_relative_to(project):
        parser.error("operator runtime and Semgate installation must be outside the project")
    if cfg.get("mode") != "enforce" or cfg.get("privacy_gate", {}).get("require_prepared") is not True or "development" not in settings:
        parser.error("guarded agent requires the strict prepared development profile")
    from .taskcontext import request_for
    try:
        trusted_request = request_for(cfg, task=settings["task_id"], project=str(project))
    except (ValueError, KeyError):
        parser.error("guarded agent requires active operator-owned task_context")
    if args.prompt != trusted_request:
        parser.error("prompt does not match the protected task request; operator must bind the new task first")
    home = create_home(state, model=args.model, base_url=args.base_url, env_key=args.env_key)
    def emit(value):
        if event is not None:
            event(value)
        if value.get("method") in {"semgate/receipt", "item/agentMessage/delta"}:
            print(json.dumps(value), flush=True)
    try:
        receipt = CodexRunner(args.codex_bin, home, Path(settings["client_file"]), timeout_s=args.timeout_s, event=emit, env=env).run(args.prompt)
        print(json.dumps(receipt))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "service_error", "reason_code": "guarded_agent_stopped", "error_type": type(exc).__name__}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
