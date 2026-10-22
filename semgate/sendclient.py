"""Small agent client, executable with python -I /absolute/path/sendclient.py.

The standalone path uses only the standard library. It never imports an
agent-project module, retries a dispatch, follows redirects, or falls back to
running the upload command. verified_invocation is used only by the hook.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_ID = re.compile(r"[0-9a-f]{32}\Z")


def development_invocation(command: str, connection: Path, *, python: Path | None = None) -> str:
    """Canonical shell spelling: command text is one literal client argument."""
    arguments = [Path(python or sys.executable).as_posix(), "-I", Path(__file__).resolve().as_posix(),
                 "run", command, "--connection", connection.resolve().as_posix()]
    if os.name == "nt":
        return "& " + " ".join("'" + arg.replace("'", "''") + "'" for arg in arguments)
    import shlex
    return shlex.join(arguments)


def _development_invocation(command, settings):
    if not isinstance(settings.get("development"), dict):
        return False
    connection = Path(settings["client_file"]).resolve()
    if ".semgate" not in {p.name.lower() for p in connection.parents}:
        return False
    if os.name == "nt":
        template = development_invocation("SEMGATE_COMMAND", connection)
        left, right = template.split("'SEMGATE_COMMAND'")
        if not command.startswith(left) or not command.endswith(right):
            return False
        quoted = command[len(left):-len(right)]
        if not re.fullmatch(r"'(?:[^']|'')*'", quoted):
            return False
        target = quoted[1:-1].replace("''", "'")
    else:
        import shlex
        words = shlex.split(command)
        if len(words) != 7:
            return False
        target = words[4]
    return (isinstance(target, str) and 0 < len(target) <= 4096 and "\0" not in target
            and development_invocation(target, connection) == command)


def verified_invocation(envelope, config) -> bool:
    """Narrow trusted effect contract, not an agent-supplied tool flag."""
    settings = config.get("prepared_sends", {})
    if (not isinstance(settings, dict) or settings.get("enabled") is not True
            or envelope.action.tool not in {"bash", "shell", "run_command", "powershell"}):
        return False
    command = str(envelope.action.arguments.get("command", "")).strip()
    try:
        if _development_invocation(command, settings):
            return True
    except (ValueError, KeyError, OSError):
        return False
    if os.name == "nt" and command.startswith("& "):
        command = command[2:].lstrip()
    if any(c in command for c in ";&|<>`$%\r\n"):
        return False
    from . import shellparse
    try:
        commands = shellparse.split_commands(command)
        if len(commands) != 1 or commands[0].heredocs:
            return False
        tokens = commands[0].tokens
        if any(t.redirect or t.substitutions for t in tokens):
            return False
        words = [t.value for t in tokens]
        if len(words) != 7 or words[1] != "-I" or words[5] != "--connection":
            return False
        if Path(words[0]).resolve() != Path(sys.executable).resolve() or Path(words[2]).resolve() != Path(__file__).resolve():
            return False
        if words[3] not in {"prepare", "dispatch"} or not (_NAME if words[3] == "prepare" else _ID).fullmatch(words[4]):
            return False
        expected = Path(settings["client_file"]).expanduser().resolve()
        if ".semgate" not in {p.name.lower() for p in expected.parents}:
            return False
        return Path(words[6]).resolve() == expected
    except (OSError, ValueError, KeyError):
        return False


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(connection: Path, action: str, target) -> dict:
    if action not in {"prepare", "dispatch", "run", "write"}:
        raise ValueError("unknown broker action")
    if action == "write":
        from .devworker import validate_write
        target = validate_write(target)
    with connection.expanduser().open("rb") as stream:
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise ValueError("connection limit")
    config = json.loads(raw)
    if set(config) != {"schema", "base_url", "token_file"} or config["schema"] != "semgate-send-client/1":
        raise ValueError("invalid connection")
    url = config["base_url"]
    parts = urlsplit(url)
    if parts.username is not None or parts.password is not None or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ValueError("invalid broker URL")
    if parts.scheme != "https":
        if parts.scheme != "http" or not ipaddress.ip_address(parts.hostname or "").is_loopback:
            raise ValueError("broker must use HTTPS or literal loopback HTTP")
    token_path = Path(config["token_file"])
    if not token_path.is_absolute():
        token_path = connection.expanduser().resolve().parent / token_path
    token = token_path.read_text().strip()
    if not 16 <= len(token) <= 4096 or any(c.isspace() for c in token):
        raise ValueError("invalid broker token")
    body = target if action == "write" else {"route": target} if action == "prepare" else {"command": target} if action == "run" else {"prepared_id": target}
    req = Request(url.rstrip("/") + "/v1/send/" + action, data=json.dumps(body).encode(),
                  headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
    maximum = 262144 if action in {"run", "write"} else 65536
    with build_opener(ProxyHandler({}), _NoRedirect()).open(req, timeout=650 if action in {"run", "write"} else 30) as response:
        data = response.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("broker response limit")
    result = json.loads(data)
    # Do not echo arbitrary server text into the agent transcript.
    safe = {}
    for key in ("prepared_id", "request_id", "grant_id", "approval_id"):
        if result.get(key) and _ID.fullmatch(str(result[key])):
            safe[key] = result[key]
    for key, allowed in (("disposition", {"allow", "deny", "needs_consent", "needs_inspection", "service_error"}),
                         ("delivery", {"not_sent", "response_received", "unknown"})):
        if result.get(key) in allowed:
            safe[key] = result[key]
    if "disposition" not in safe:
        raise ValueError("invalid broker outcome")
    code = result.get("reason_code", "")
    if isinstance(code, str) and re.fullmatch(r"[a-z0-9_:/.-]{1,128}", code):
        safe["reason_code"] = code
    if isinstance(result.get("digest"), str) and re.fullmatch(r"[0-9a-f]{64}", result["digest"]):
        safe["digest"] = result["digest"]
    if type(result.get("status")) is int and 100 <= result["status"] <= 599:
        safe["status"] = result["status"]
    if action in {"run", "write"}:
        snapshot = result.get("script_snapshot")
        if (isinstance(snapshot, dict) and set(snapshot) == {"path", "sha256", "profile"}
                and snapshot.get("profile") == "isolated-python-readonly/1"
                and isinstance(snapshot.get("path"), str) and 1 <= len(snapshot["path"]) <= 512
                and isinstance(snapshot.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", snapshot["sha256"])):
            safe["script_snapshot"] = dict(snapshot)
        cleanup = result.get("cache_cleanup")
        if (isinstance(cleanup, dict) and cleanup.get("path") == "__pycache__"
                and (cleanup == {"path": "__pycache__", "state": "absent"}
                     or set(cleanup) == {"path", "state", "recovery_id"} and cleanup.get("state") == "retained"
                     and isinstance(cleanup.get("recovery_id"), str) and _ID.fullmatch(cleanup["recovery_id"]))):
            safe["cache_cleanup"] = dict(cleanup)
        audit = result.get("alias_audit")
        if (isinstance(audit, dict) and set(audit) == {"checked", "unverifiable", "offenders"}
                and type(audit.get("checked")) is int and audit["checked"] >= 0
                and type(audit.get("unverifiable")) is int and audit["unverifiable"] >= 0
                and isinstance(audit.get("offenders"), list) and len(audit["offenders"]) <= 32
                and all(isinstance(p, str) and 0 < len(p) <= 1024 and "\0" not in p for p in audit["offenders"])):
            safe["alias_audit"] = {"checked": audit["checked"], "unverifiable": audit["unverifiable"],
                                   "offenders": list(audit["offenders"])}
        for key in ("stdout", "stderr"):
            if isinstance(result.get(key), str):
                safe[key] = result[key][:16384]
        if type(result.get("exit_code")) is int:
            safe["exit_code"] = result["exit_code"]
        for key in ("timed_out", "output_truncated"):
            if type(result.get(key)) is bool:
                safe[key] = result[key]
        if result.get("boundary") == "bubblewrap-offline/1":
            safe["boundary"] = result["boundary"]
        if re.fullmatch(r"\d+\.\d+\.\d+", str(result.get("launcher_version", ""))):
            safe["launcher_version"] = result["launcher_version"]
        if re.fullmatch(r"[0-9a-f]{64}", str(result.get("launcher_sha256", ""))):
            safe["launcher_sha256"] = result["launcher_sha256"]
    return safe


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Use the configured prepared-send harness")
    parser.add_argument("action", choices=("prepare", "dispatch", "run"))
    parser.add_argument("target")
    parser.add_argument("--connection", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.action == "run":
        if not 0 < len(args.target) <= 4096 or "\0" in args.target:
            parser.error("invalid development command")
    elif not (_NAME if args.action == "prepare" else _ID).fullmatch(args.target):
        parser.error("invalid route or prepared id")
    try:
        result = request(args.connection, args.action, args.target)
    except Exception:
        result = {"disposition": "service_error", "reason_code": "prepared_client_error",
                  "delivery": "unknown" if args.action == "dispatch" else "not_sent"}
        print(json.dumps(result))
        return 2
    print(json.dumps(result, sort_keys=True))
    if args.action == "run":
        code = result.get("exit_code")
        if result.get("disposition") != "allow" or result.get("timed_out") or type(code) is not int:
            return 2
        return code
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
