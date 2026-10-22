"""Where the paths in a semgate.json point. Never relative to the current directory.

A hook runs with the agent's project folder as its current directory, so a
path resolved against it lands in whatever project the agent works in. The
rule below uses only the config file's own location and the home folder.

Rule (resolve()):

1. `~` expands to the home folder.
2. A relative path resolves against the config's base folder: the folder
   that holds the config file; when that folder is a host config folder (its
   name starts with a dot: `.antigravity`, `.claude`, `.gemini`), the folder
   above it. Example: config
   `/home/me/proj/.antigravity/semgate.json`, base
   `/home/me/proj`, so `.antigravity/semgate/ledger.jsonl`
   is `/home/me/proj/.antigravity/semgate/ledger.jsonl`:
   the file the relative path meant when the hook ran from the repo folder.
   Config `~/.semgate/claude/semgate.json`: base `~/.semgate/claude`.
3. An absolute path is kept as written (the same string).
4. `ledger_file` not set: `~/.semgate/<host>/ledger.jsonl`.
5. Other stores not set: next to `ledger_file` (state_path()):
   tool_history.jsonl, feedback.jsonl, deny_streak.json, tool_outputs/,
   own_messages/, exposures/, fingerprint.key.
   Unchanged defaults: `agent_files.dir` is `~/.semgate`; `profiles.state_file`
   not set means no state file; `policy_file` not set is the packaged policy;
   `trust.file` not set is `~/.semgate/trust.jsonl` (one store for every host).

Only a relative `--config` path itself still depends on the current
directory (it is a command-line argument); every installed hook passes an
absolute one.
"""
from __future__ import annotations

import copy
import json
import os
import re
from typing import Any, Dict, List, Mapping, Optional, Tuple

# (dotted key, the file name next to the ledger when the key is not set, or None: no default here)
PATH_KEYS: Tuple[Tuple[Tuple[str, ...], Optional[str]], ...] = (
    (("ledger_file",), None),
    (("grant_file",), None),
    (("policy_file",), None),
    (("auto_allow_learned", "history_file"), "tool_history.jsonl"),
    (("feedback", "feedback_file"), "feedback.jsonl"),
    (("enforcement", "deny_escalation", "state_file"), "deny_streak.json"),
    (("profiles", "file"), None),
    (("profiles", "state_file"), None),
    (("tool_outputs", "dir"), "tool_outputs"),
    (("own_messages", "dir"), "own_messages"),
    (("secret_exposures", "dir"), "exposures"),
    (("secret_exposures", "key_file"), "fingerprint.key"),
    (("agent_files", "dir"), None),
    (("trust", "file"), None),
    (("prepared_sends", "project_root"), None),
    (("prepared_sends", "client_file"), None),
    (("prepared_sends", "consent_store"), None),
)
AGENT_FILES_DEFAULT = "~/.semgate"


def host_dir(host: str) -> str:
    """`~/.semgate/<host>` (the user-level state folder of `semgate init <host>`)."""
    name = re.sub(r"[^A-Za-z0-9._-]", "", str(host or "")).strip(".") or "unknown"
    return os.path.join(os.path.expanduser("~"), ".semgate", name)


def host_ledger(host: str) -> str:
    return os.path.join(host_dir(host), "ledger.jsonl")


def base_dir(config_path: str) -> str:
    """The folder relative paths in `config_path` resolve against (rule 2)."""
    folder = os.path.dirname(os.path.abspath(os.path.expanduser(str(config_path))))
    if os.path.basename(folder).startswith("."):
        folder = os.path.dirname(folder)
    return folder


def guess_host(config_path: str) -> str:
    """The host a config belongs to, from where it is: `.../.antigravity/x.json`
    -> antigravity, `~/.semgate/<host>/semgate.json` -> <host>, else unknown."""
    folder = os.path.dirname(os.path.abspath(os.path.expanduser(str(config_path))))
    name = os.path.basename(folder)
    if name.startswith(".") and len(name) > 1:
        return name[1:]
    if os.path.basename(os.path.dirname(folder)) == ".semgate" and name:
        return name
    return "unknown"


def resolve_path(value: str, base: str) -> str:
    expanded = os.path.expanduser(value)
    if os.path.isabs(expanded):
        return expanded
    return os.path.normpath(os.path.join(base, expanded))


def resolve(config: Mapping[str, Any], config_path: str, host: str) -> Dict[str, Any]:
    """A copy of `config` with every path key absolute (rules 1-4). The input
    is not changed. A value that is not a non-empty string is left as it is."""
    out: Dict[str, Any] = copy.deepcopy(dict(config))
    base = base_dir(config_path)
    for keys, _default in PATH_KEYS:
        node: Any = out
        for k in keys[:-1]:
            node = node.get(k) if isinstance(node, dict) else None
        if isinstance(node, dict):
            value = node.get(keys[-1])
            if isinstance(value, str) and value.strip():
                node[keys[-1]] = resolve_path(value, base)
    ledger = out.get("ledger_file")
    if not (isinstance(ledger, str) and ledger.strip()):
        out["ledger_file"] = host_ledger(host)
    return out


def load(config_path: str, host: str) -> Dict[str, Any]:
    """Read a semgate.json (a JSON object) and resolve() it. Raises OSError
    or ValueError like antigravity_hook.load_json."""
    with open(os.path.expanduser(str(config_path)), encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{config_path} must contain a JSON object")
    return resolve(value, config_path, host)


# ---------------------------------------------------------------- accessors (resolved or in-process configs)


def ledger_file(config: Mapping[str, Any]) -> str:
    """`ledger_file`, or `~/.semgate/unknown/ledger.jsonl` for a config that
    did not go through resolve() and has none (never a path under the
    current directory)."""
    value = config.get("ledger_file") if isinstance(config, Mapping) else None
    if isinstance(value, str) and value.strip():
        return os.path.expanduser(value)
    return host_ledger("unknown")


def state_path(config: Mapping[str, Any], name: str) -> str:
    """`name` in the folder of ledger_file(config) (rule 5)."""
    return os.path.normpath(os.path.join(os.path.dirname(ledger_file(config)), name))


def _get(config: Mapping[str, Any], keys: Tuple[str, ...]) -> Any:
    node: Any = config
    for k in keys:
        node = node.get(k) if isinstance(node, Mapping) else None
    return node


def store_paths(config: Mapping[str, Any], host: str = "") -> List[Tuple[str, str]]:
    """[(label, absolute path)] of every store the config writes, as the hooks
    compute them (for `semgate doctor`). A store that is off is left out, and
    so are the tool output and exposure stores for antigravity (its post hook
    does not get the tool's output)."""
    from . import exposures, fingerprints, ownmessages, tooloutputs
    from .antigravity_hook import agent_files_enabled, feedback_path, history_path, script_source_enabled
    out: List[Tuple[str, str]] = [("ledger", ledger_file(config))]
    if history_path(config):
        out.append(("history", history_path(config)))
    if feedback_path(config):
        out.append(("feedback", feedback_path(config)))
    esc = _get(config, ("enforcement", "deny_escalation"))
    if isinstance(esc, Mapping) and esc.get("enabled") is True:
        out.append(("deny_streak", deny_streak_file(config)))
    prof = config.get("profiles") if isinstance(config.get("profiles"), Mapping) else {}
    if prof.get("enabled") is True and str(prof.get("state_file") or ""):
        out.append(("profile_state", os.path.expanduser(str(prof["state_file"]))))
    if host != "antigravity" and tooloutputs.enabled(config):
        out.append(("tool_outputs", str(tooloutputs.store_dir(config))))
    if ownmessages.enabled(config):
        out.append(("own_messages", str(ownmessages.store_dir(config))))
    if host != "antigravity" and exposures.enabled(config):
        out.append(("exposures", str(exposures.store_dir(config))))
        out.append(("fingerprint_key", str(fingerprints.key_path(config))))
    if agent_files_enabled(config) or script_source_enabled(config):
        out.append(("agent_files", agent_files_dir(config)))
    from . import trust
    if trust.enabled(config):
        out.append(("trust", str(trust.store_path(config))))
    return out


def deny_streak_file(config: Mapping[str, Any]) -> str:
    esc = _get(config, ("enforcement", "deny_escalation"))
    value = esc.get("state_file") if isinstance(esc, Mapping) else None
    if isinstance(value, str) and value.strip():
        return os.path.expanduser(value)
    return state_path(config, "deny_streak.json")


def agent_files_dir(config: Mapping[str, Any]) -> str:
    af = config.get("agent_files") if isinstance(config.get("agent_files"), Mapping) else {}
    return os.path.normpath(os.path.expanduser(str(af.get("dir") or AGENT_FILES_DEFAULT)))
