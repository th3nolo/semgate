"""Deterministic hard rules and absolute human gates.

Order of precedence inside the judge:
  1. hard deny   (grant scope violations, forbidden patterns, denylisted commands)
  2. human gates (credentials/secrets, money, external communication,
                  destructive/irreversible, privilege escalation) -> forced ASK,
                  the semantic provider is never consulted and can never
                  override a gate
  3. hard allow  (small conservative read-only set, fully inside grant scope)
  4. semantic layer (only what survives 1-3)

Everything in this module is pure pattern/logic over the envelope. No model,
no provider, no side effects.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Tuple

from . import adminguard, catastrophic, injection, linkplace, shellparse
from .envelope import Envelope
from .trust import TRUST_REQUEST_RE

# Redirect sinks that write nothing to disk: `2>/dev/null`, `> /dev/stdout`,
# `/dev/stderr`, `/dev/fd/N`. A redirect to one of these is not an overwrite
# and not a write into a system directory. `/dev/sda` and `/dev/nullx` still
# match. Used as a negative lookahead right after the redirect's leading `/`.
_DEV_SINK = r"dev/(?:null|stdout|stderr|fd/\d+)(?=[\s;&|)<>\"']|$)"
# Where hosts keep the session record semgate reads the user's turns from:
# Claude Code (~/.claude/projects/<project>/<session>.jsonl), agy
# (~/.gemini/antigravity/brain/<conversation>/...transcript*.jsonl), OpenCode
# (~/.local/share/opencode/storage/...).
_HOST_TRANSCRIPTS = r"(\.claude[/\\]+projects[/\\]|\.gemini[/\\]+antigravity[/\\]+brain[/\\]|opencode[/\\]+storage[/\\])"
# Agent config and permission files, and the folders a host loads plugins or
# extensions from (semgate's own plugin copies live there):
#   Claude Code  ~/.claude/settings(.local).json, <project>/.claude/settings*.json
#   Codex        ~/.codex/config.toml, hooks.json
#   Cursor       .cursor/hooks*, rules, mcp*
#   OpenCode     ~/.config/opencode/ (config, plugins), <project>/.opencode/plugin(s)/
#   Gemini/agy   ~/.gemini/settings.json, ~/.gemini/config/ (hooks.json is a hard deny)
#   Copilot      ~/.copilot/hooks/
#   Grok         ~/.grok/hooks
#   Pi           ~/.pi/agent/ (extensions, settings.json, trust.json, auth.json,
#                sessions), <project>/.pi/extensions/, <project>/.pi/settings.json
#   Droid        ~/.factory/hooks.json, settings(.local).json, mcp.json, config.json
_AGENT_CONFIG_PATHS = (
    r"(\.claude[/\\]+settings(\.local)?\.json|\.codex[/\\]+(config\.toml|hooks\.json)|\.cursor[/\\]+(hooks|rules|mcp)|"
    r"\.config[/\\]+opencode[/\\]|\.gemini[/\\]+settings\.json|\.gemini[/\\]+config[/\\]|\.copilot[/\\]+hooks|"
    r"\.grok[/\\]+hooks|\.opencode[/\\]+plugins?[/\\]|\.pi[/\\]+agent[/\\]|\.pi[/\\]+(extensions[/\\]|settings\.json)|"
    r"\.factory[/\\]+(hooks|settings(\.local)?|mcp|config)\.json)")
AGENT_CONFIG_PATH_RE = re.compile(_AGENT_CONFIG_PATHS, re.IGNORECASE)
# Shell ways to create, change, move or delete a file (redirects, tee, sed -i,
# and the move / copy / delete / write commands of sh, cmd and PowerShell).
_AGENT_CONFIG_WRITE = (r"(>>?|\btee\b|\bsed\s+-i\S*|\bperl\b[^\n|;&]*\s-\w*i|\b(rm|rmdir|rd|ri|mv|cp|copy|move|ren|rename|"
                       r"del|erase|unlink|truncate|shred|touch|ln|mklink|install|remove-item|move-item|copy-item|"
                       r"rename-item|set-content|add-content|clear-content|out-file|new-item)\b)")

# Destructive patterns, each with a flag: True when the pattern only deletes,
# overwrites or discards FILES, which git (or a snapshot) can bring back when
# the targets are clean. `recoverable_destructive_only` reads this flag from
# the compiled pattern objects, so the relaxable set cannot drift from the
# gate list (it used to be a second copy of the pattern strings).
_DESTRUCTIVE_SPECS: Tuple[Tuple[str, bool], ...] = (
    (r"\brm\s+-[a-z]*[rf]", True),
    (r"\brm\s+[^\n]*", True),
    (r"\bshred\b", False),
    (r"\btruncate\b", False),
    (r"\bgit\s+push\s+[^\n]*--force", False),
    (r"\bgit\s+reset\s+--hard", False),
    (r"\bgit\s+clean\s+-[a-z]*f", False),
    # discarding uncommitted work: git checkout -- <path> / . / -f, git restore
    # (not --staged alone, which only unstages), git switch --discard-changes
    (r"\bgit\s+checkout\b[^\n]*(\s--(\s|$)|\s\.(\s|$)|\s-f\b|\s--force\b)", True),
    (r"\bgit\s+restore\b(?![^\n]*--staged(?![^\n]*--worktree))", True),
    (r"\bgit\s+switch\b[^\n]*\s(--discard-changes|-f|--force)\b", True),
    (r"\bdrop\s+(table|database)\b", False),
    (r"\bdelete\s+from\b", False),
    (r">\s*/(?!" + _DEV_SINK + r")[^ ]", True),               # shell overwrite redirect to absolute path (not /dev/null & co.)
    (r"\bkill\s+-9\b", False),
    (r"\bxargs\b[^\n|;&]*\brm\b", False),                              # find ... | xargs rm (file list comes from the pipe)
    (r"\bfind\b[^\n]*\s(-delete\b|-exec\s+rm\b|-execdir\s+rm\b)", False),  # find -delete / -exec rm
    (r"\b(pkill|killall)\b", False),                                   # kill by name: hits every matching process
    (r"\bps\s+-e[a-z]*\b[\s\S]*\bkill\b|\bkill\b[\s\S]*\bps\s+-e[a-z]*\b", False),  # enumerate all processes, then kill
    (r"\bshutil\.rmtree\s*\(|\bos\.removedirs\s*\(", False),           # recursive delete from an inline python snippet
    # Windows recursive deletes inside the project (drive roots and
    # system folders are hard-denied in HARD_DENY_PATTERNS).
    (r"\b(remove-item|ri|rm|del|erase)\b[^\n]*\s-r(ecurse)?\b", True),
    (r"\b(del|erase|rd|rmdir)\b[^\n]*\s/s\b", True),
    # git: history and refs that are hard or impossible to get back
    (r"\bgit\s+branch\b[^\n]*\s((?-i:-D)|--delete\s+--force|--force\s+--delete)\b", False),   # -D forces; -d (merged only) is safe
    (r"\bgit\s+stash\s+(drop|clear)\b", False),
    (r"\bgit\s+reflog\s+(expire|delete)\b", False),
    (r"\bgit\s+gc\b[^\n]*--prune", False),
    (r"\bgit\s+(filter-branch|filter-repo)\b", False),
    (r"\bgit\s+update-ref\s+-d\b", False),
    (r"\bgit\s+push\b[^\n]*(\s--mirror\b|\s--delete\b|\s-d\s|\s:[^\s:]+)", False),
    (r"\bgit\s+worktree\s+remove\b[^\n]*\s(-f|--force)\b", False),
    # Bulk permission/group changes: the old modes are lost for every file hit
    # (chown is already a privilege_escalation gate). A single named file
    # (`chmod +x build.sh`) is not bulk and is not matched.
    (r"\b(chmod|chgrp)\b[^\n|;&]*\s(-[a-zA-Z]*R[a-zA-Z]*|--recursive)\b", False),
    (r"\bfind\b[^\n]*\s-exec(dir)?\s+(chmod|chgrp|chown)\b", False),
    (r"\bxargs\b[^\n|;&]*\b(chmod|chgrp|chown)\b", False),
    (r"\b(chmod|chgrp)\b[^\n|;&]*\s(?!['\"])[^\s|;&'\"]*[*?][^\s|;&'\"]*", False),   # unquoted glob (the shell expands it)
    # Bulk in-place edits: every matching file is rewritten. Relaxable: when
    # git state verifies every target is tracked and clean, git can restore it;
    # with xargs/find the targets are unknown to code, so it still asks.
    (r"\bxargs\b[^\n|;&]*\b(sed|perl)\b[^\n|;&]*\s-[a-zA-Z]*i", True),
    (r"\bfind\b[^\n]*\s-exec(dir)?\s+(sed|perl)\b[^\n]*\s-[a-zA-Z]*i", True),
    (r"\bsed\b[^\n|;&]*\s-[a-zA-Z]*i\b[^\n|;&]*\s(?!['\"])[^\s|;&'\"]*[*?][^\s|;&'\"]*", True),   # unquoted glob, not a quoted sed script
    # databases
    (r"\bdropdb\b", False),
    (r"\bdrop\s+(schema|index|view|user|role|collection|keyspace)\b", False),
    (r"\b(flushall|flushdb)\b", False),
    (r"\bdropDatabase\s*\(|\.drop\s*\(\s*\)", False),
    # infrastructure and cloud
    (r"\bterraform\s+destroy\b|\bterraform\s+apply\b[^\n]*-auto-approve\b|\bpulumi\s+destroy\b", False),
    (r"\bkubectl\s+delete\b", False),
    (r"\bhelm\s+(uninstall|delete)\b", False),
    (r"\bdocker\s+(system|volume|image|container|network|builder)\s+prune\b", False),
    (r"\bdocker\s+(rm|rmi)\b[^\n]*\s(-f|--force)\b", False),
    (r"\baws\s+s3\s+(rm\b[^\n]*--recursive|rb\b)", False),
    (r"\baws\s+[a-z0-9-]+\s+(delete|terminate|deregister|purge)-[a-z0-9-]+", False),
    (r"\b(az|gcloud|doctl)\b[^\n]*\s(delete|purge)\b", False),
    # disks, volumes, Windows system state
    (r"\b(wipefs|fdisk|sfdisk|sgdisk|parted|lvremove|vgremove|pvremove)\b", False),
    (r"\bremove-partition\b|\bclear-recyclebin\b", False),
    (r"\breg\s+delete\b", False),
    (r"\bnet\s+(user|localgroup)\b[^\n]*\s/delete\b", False),
    (r"\bwsl\s+--unregister\b", False),
    (r"\brobocopy\b[^\n]*\s/(mir|purge)\b", False),
)

# Network use from inside code the command runs (python -c, node -e, a heredoc
# fed to an interpreter, a script file under F4). Checked only against the
# extracted code, never against the whole command line, so a
# `grep -rn requests.get src/` is not gated. Gate class: embedded_execution.
SCRIPT_NETWORK_PATTERNS: Tuple[re.Pattern, ...] = tuple(
    re.compile(p)
    for p in (
        r"\burllib\.request\b|\bfrom\s+urllib\s+import\s+[^\n]*\brequest\b",
        r"\burllib3\b",
        r"\brequests\.(get|post|put|patch|delete|head|request|Session)\s*\(",
        r"\bhttp\.client\b|\bfrom\s+http\s+import\s+[^\n]*\bclient\b",
        r"\bhttpx\b",
        r"\bsocket\.(socket|create_connection)\s*\(",
        r"\b(smtplib|ftplib|aiohttp)\b",
        # node
        r"\bhttps?\.(request|get)\s*\(",
        r"(?<![\w.$])fetch\s*\(",
        r"\bnet\.(connect|createConnection)\s*\(",
        r"\brequire\s*\(\s*[\"'](node:)?(https?|http2|net|tls|dgram)[\"']\s*\)|\bfrom\s+[\"'](node:)?(https?|http2|net|tls|dgram)[\"']",
        # ruby / perl
        r"\bNet::HTTP\b|\bLWP::|\bIO::Socket\b|\bTCPSocket\b",
    )
)

# Tools that never mutate anything. Only these are eligible for hard allow.
DEFAULT_HARD_ALLOW_TOOLS: Tuple[str, ...] = ("read", "glob", "grep", "ls", "lsp")

# semgate's own state folder (~/.semgate: config, grant, ledger, feedback,
# trust store, approval tickets, agent-host record, keys) named in a command:
# `.semgate` after a path separator, a quote, a space or `=(:,`, and before a
# separator, a quote, a space or the end. `foo.semgate` is not one.
_SEMGATE_REF = r"""(?:^|[\s/\\'"=(:,`])\.semgate(?=[/\\'"\s),;`]|$)"""
# Commands and APIs that create, change, move or delete files (shell, cmd,
# PowerShell, .NET). Used with _SEMGATE_REF after them on the same line.
_WRITE_VERBS = (r"""(?:\b(?:remove-item|move-item|rename-item|clear-content|set-content|add-content|out-file|new-item|"""
                r"""copy-item|set-acl|del|erase|move|ren|rename|rm|rmdir|mv|cp|copy|xcopy|robocopy|tee|truncate|"""
                r"""install|ln|mklink|touch|rsync|dd|tar|unzip|7z|shred|unlink|chmod|chown|icacls|attrib|takeown)\b"""
                r"""|\bsed\b[^\n|;&]*\s-[a-z]*i|\bperl\b[^\n|;&]*\s-[a-z]*i"""
                r"""|\b(?:curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n|;&]*\s(?:-o|--output|"""
                r"""--output-document|-outfile)\b"""
                r"""|\[(?:system\.)?io\.(?:file|directory)\]::(?:write|append|copy|move|delete|replace|create|open|set)\w*)""")
# A redirect that writes a file (not a descriptor copy, not a null device).
_WRITE_REDIRECT = r""">>?(?!\s*&)(?!\s*(?:/dev/(?:null|stdout|stderr)|\$null|nul)\b)"""
# Code (python -c, node -e, heredocs) that writes files: open(..., "w"/"a"/
# "x"/"+"), pathlib / os / shutil / fs writers. With a `.semgate` mention in
# the same code it is a write to semgate's state (check_hard_deny).
_CODE_WRITE_RE = re.compile(
    r"""\bopen\s*\([^)]*,\s*(?:mode\s*=\s*)?['"][rwxabt+]*[wax+][rwxabt+]*['"]"""
    r"""|\.open\s*\(\s*(?:mode\s*=\s*)?['"][rwxabt+]*[wax+][rwxabt+]*['"]"""
    r"""|\.write_(?:text|bytes)\s*\(|\bshutil\.(?:copy\w*|move|rmtree)\b"""
    r"""|\bos\.(?:replace|rename\w*|remove|unlink|rmdir|removedirs|symlink|link|truncate|makedirs|mkdir|chmod)\b"""
    r"""|\.(?:unlink|rename|replace|symlink_to|hardlink_to|touch|rmdir|chmod)\s*\("""
    r"""|\b(?:write|append)File(?:Sync)?\b|\bfs(?:\.promises)?\.(?:rm\w*|unlink\w*|rename\w*|copyFile\w*|cp\w*|"""
    r"""symlink\w*|link\w*|truncate\w*|createWriteStream|open\w*|mkdir\w*|chmod\w*)\b"""
    r"""|\bFile\.(?:write|open|delete|rename|symlink)|\bFileUtils\.|\bIO\.(?:write|binwrite)""", re.IGNORECASE)
_CODE_SEMGATE_RE = re.compile(r"\.semgate\b", re.IGNORECASE)

# Commands that are denied outright regardless of grant or model opinion.
# MULTILINE: the searched text has one argument per line, so `$` must match at
# the end of the command's line, not only at the end of the whole text.
# The three rm patterns see only one spelling; check_hard_deny also runs the
# parsed rule in catastrophic.py (rm -fr /, rm -r -f /, --no-preserve-root,
# find / -delete, chmod -R on / or the home folder, ...).
HARD_DENY_PATTERNS: Tuple[re.Pattern, ...] = tuple(
    re.compile(p, re.IGNORECASE | re.MULTILINE)
    for p in (
        r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+/\s*$",      # rm -rf /
        r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+/\*",        # rm -rf /*
        r"rm\s+-[a-z]*r[a-z]*f[a-z]*\s+~",          # rm -rf ~
        r"\bmkfs\b",
        r"\bdd\b[^\n]*\bof=/dev/",
        r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;",    # fork bomb
        r"\bshutdown\b",
        r"\breboot\b",
        r"\b(stop|restart)-computer\b",             # PowerShell shutdown/restart
        # Windows / PowerShell / cmd catastrophic patterns. agy and Gemini CLI
        # run these on Windows, where the Unix rm patterns above never match.
        # Kept narrow: always-catastrophic tools, or a delete aimed at a drive
        # root or a system directory - not ordinary in-project deletes.
        r"\bformat-volume\b",
        r"\bclear-disk\b",
        r"\bdiskpart\b",
        r"\bcipher\b[^\n]*\s/w[:\s]",               # cipher /w: secure-wipe
        r"\bformat\s+[a-z]:",                        # format c:
        r"\b(remove-item|rd|rmdir|del|erase)\b[^\n]*\b[a-z]:\\?(\s|$|[\"'*])",          # delete of a bare drive root (C:\ , C:\*)
        r"\b(remove-item|rd|rmdir|del|erase)\b[^\n]*\b[a-z]:\\(windows|program files|system32)\b",  # delete of a system dir
        # Encoded / remote execution: the encoding itself is the red flag; we do
        # not need to decode it. These shapes are almost never legitimate dev.
        r"\b(powershell|pwsh)\b[^\n]*\s-e(nc(odedcommand)?)?\b",   # powershell -EncodedCommand <base64>
        r"\bcertutil\b[^\n]*-(decode|urlcache)\b",                 # certutil decode/download payloads
        r"\b(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod|base64)\b[^\n]*\|[^\n]*\b(iex|invoke-expression|sh|bash|zsh|python|node|pwsh|powershell)\b",  # download | execute
        # Self-protection: the agent must never disable or rewrite Semgate's own
        # gate config. A mutating verb or a redirect aimed at the hook/enforce/
        # grant/policy config is denied outright. Reading the config stays allowed.
        r"\b(remove-item|move-item|rename-item|clear-content|set-content|add-content|out-file|del|erase|move|ren|rename|rm|mv|cp|copy-item)\b[^\n]*\.(agents|antigravity)\b[^\n]*(hooks|semgate|grant|polic)",
        r">>?\s*[^\n|]*\.(agents|antigravity)\b[^\n]*(hooks|semgate)",
        # Since agy 1.2.8 the hook is registered at the user level
        # (~/.gemini/config/hooks.json) and `semgate init` keeps its config in
        # ~/.semgate/. Mutating either (verb, redirect, tee, sed -i, python open)
        # would switch the gate off. Reading them stays allowed.
        r"\b(remove-item|move-item|rename-item|clear-content|set-content|add-content|out-file|new-item|del|erase|move|ren|rename|rm|mv|cp|copy-item|tee|truncate)\b[^\n]*\.gemini[/\\]+config[/\\]+hooks\.json",
        r"(>>?|\bsed\s+-i\S*\b[^\n]*|open\([^\n]*)\s*['\"]?[^\n|;&]*\.gemini[/\\]+config[/\\]+hooks\.json",
        # ~/.semgate holds the trust store, the approval tickets and the key
        # that tags them (trustauth.py): a write command or API aimed at it,
        # a redirect into it, a `cd` into it followed by any write, or `find
        # ... -delete` / `xargs rm` over it.
        _WRITE_VERBS + r"[^\n]*" + _SEMGATE_REF,
        _WRITE_REDIRECT + r"\s*[^\n|;&<>]*" + _SEMGATE_REF,
        r"\b(?:cd|pushd|set-location|sl|chdir)\b[^\n;&|]*" + _SEMGATE_REF + r"[\s\S]*?(?:" + _WRITE_REDIRECT + "|"
        + _WRITE_VERBS + ")",
        _SEMGATE_REF + r"[^\n]*(?:\s-delete\b|\s-exec\b[^\n]*\b(?:rm|mv|cp|tee|truncate|sed|chmod)\b"
                       r"|\bxargs\b[^\n]*\b(?:rm|mv|cp|tee|truncate|sed|chmod)\b)",
        # The agent must never approve its own actions: only the human runs this.
        r"\bsemgate\b[^\n]*\bfeedback\b[^\n]*\ballow\b",
        r"semgate[._]feedback[^\n]*allow",
        # Code that opens a file under a .semgate folder for writing (the
        # stores: feedback, trust, ledger). The verb and redirect patterns
        # above do not see python/node `open(...)`.
        r"\bopen\([^\n]*[/\\]\.semgate[/\\][^\n]*['\"]([wax]b?\+?|r\+b?|rb\+)['\"]",
        # Cloud instance metadata endpoints: reaching these steals IAM/cloud
        # credentials via SSRF. Almost never legitimate dev; blocked outright.
        r"169\.254\.169\.254",
        r"\bmetadata\.google\.internal\b",
        r"\bfd00:ec2::254\b",
        # Destroying backups and recovery points: the first move of ransomware,
        # never something a coding task needs.
        r"\bvssadmin\b[^\n]*\bdelete\b[^\n]*\bshadows?\b",
        r"\bwmic\b[^\n]*\bshadowcopy\b[^\n]*\bdelete\b",
        r"\bbcdedit\b[^\n]*(/delete|recoveryenabled\s+no)",
    )
)

# Absolute human gates. A match forces ASK; the semantic layer is skipped and
# no predicate score can auto-allow the action. Deny is still possible above.
GATE_PATTERNS = {
    # `semgate trust add` / `semgate trust file`: they make semgate allow a
    # command without asking, or stop treating instruction-file lines as
    # untrusted. Any `semgate ... trust` is a human gate (except a strictly
    # parsed `trust list` / `trust remove`, trust.harmless); only
    # trustgate.py (a code check of the user's own turn, then the judge) may
    # let the agent run it. First in the table, so its reason code is
    # human_gate:trust_request.
    "trust_request": (TRUST_REQUEST_RE,),
    # semgate's admin commands (`semgate init | uninstall | harness init`
    # ...) in a form the parser in check_hard_deny cannot read: the program
    # in a variable (`S=semgate; $S init`), built by a substitution, or piped
    # (`echo init | xargs semgate`). adminguard.ADMIN_TEXT_RE; a strictly
    # parsed `semgate init --help` is left out (detect_gates). Only shell
    # commands and script files: a file tool's text is not a command.
    "semgate_admin": (adminguard.ADMIN_TEXT_RE,),
    # semgate's approval path for harnesses (semgate.harness, `semgate serve
    # --http`): the approve endpoint, the in-process approve() call, and the
    # token files `semgate harness init` writes. The human side calls these;
    # an agent that does may be approving its own blocked action, so a human
    # decides. A gate, not a hard deny: `/v1/approve` is also a common path
    # of other APIs.
    "semgate_approval": tuple(
        re.compile(p, re.IGNORECASE)
        for p in (
            r"/v1/approve\b",
            r"\bsemgate\b[^\n]*\bapprove\s*\(",
            r"\.semgate[/\\]+(?:[^\s'\"|;&<>]*[/\\])?[^\s/\\'\"|;&<>]*\.token\b",
        )
    ),
    "credentials_secrets": tuple(
        re.compile(p, re.IGNORECASE)
        for p in (
            # Anchor on /, ~, @, whitespace or a backslash so a secret is caught
            # whether it is a path, an ssh target, or a `curl -d @.env` payload.
            r"(^|[/~@\s\\])\.ssh([/\\]|$|\s)",
            r"(^|[/~@\s\\])\.env($|[.\s\"'\\])",
            r"(^|[/~@\s\\])\.aws([/\\]|$|\s)",
            r"(^|[/~@\s\\])\.gnupg([/\\]|$|\s)",
            r"(^|[/~@\s\\])\.netrc\b",
            r"id_rsa|id_ed25519|id_ecdsa",
            r"\.(pem|p12|pfx)\b|(^|[/~@\s\\])[a-z0-9_-]*\.key\b",
            r"credentials?\.(json|xml|ini|yaml|yml)\b",
            r"\bkeychain\b",
            r"(^|[/.\\])etc[/\\](passwd|group|gshadow|shadow)\b",  # system account/group files (recon), incl. ../etc/ traversal
            r"(^|[/.\\])etc[/\\]security\b",                        # PAM / security configs
            # printing the whole environment (API keys, tokens). `env VAR=x cmd`
            # and `printenv PATH` (one named variable) are not this.
            r"(^|[\n;&|]\s*)(env|printenv|set|Get-ChildItem\s+env:|gci\s+env:|dir\s+env:)[ \t]*($|[\n|>;&])",
            # CLIs whose output IS a secret or a live token
            r"\bvault\s+(kv\s+)?(get|read)\b",
            r"\baws\s+secretsmanager\s+get-secret-value\b",
            r"\baws\s+ssm\s+get-parameters?\b[^\n]*--with-decryption",
            r"\bgh\s+auth\s+token\b",
            r"\bop\s+(read|item\s+get)\b",
            r"\bgcloud\s+auth\s+(print-access-token|print-identity-token)\b",
            r"\baz\s+account\s+get-access-token\b",
            r"\bkubectl\s+get\s+secrets?\b",
            r"\bdoppler\s+secrets\b",
            r"\bgit\s+credential\s+fill\b",
        )
    ),
    "money": tuple(
        re.compile(p, re.IGNORECASE)
        for p in (
            r"\b(stripe|paypal|payment|purchase|buy\s+now|place\s+order|wire\s+transfer)\b",
            # "checkout" as in a payment checkout, not `git checkout` and not a
            # hyphenated name like checkout-flow-test.
            r"(?<!git )(?<!git  )\bcheckout\b(?!\s*[-.])",
            r"\b(send|transfer)\s+\$?\d",
            r"\binvoice\b.*\bpay\b",
            r"\b(btc|eth|crypto|wallet)\b.*\b(send|transfer|pay)\b",
            r"\brefund\b",
        )
    ),
    "external_communication": tuple(
        re.compile(p, re.IGNORECASE)
        for p in (
            r"\b(curl|wget|http|https)\b[^\n]*\s(-X\s*(POST|PUT|PATCH|DELETE)|--data|--form|-d\s)",
            r"\bmail\b|\bsendmail\b|\bmutt\b",
            r"\bgit\s+push\b",
            r"\bnpm\s+publish\b|\bpypi\s+upload\b|\btwine\s+upload\b",
            # ssh/scp/rsync/sftp with a user@host anywhere in the command, not only
            # as the first argument: `scp file user@host:` and `ssh -i key user@host`
            # are the common forms. (?![\w-]) keeps ssh-keygen / ssh-add out.
            r"\b(ssh|scp|rsync|sftp)(?![\w-])[^\n]*?[\s'\"][\w.-]+@[\w.-]+",
            r"\b(nc|ncat|netcat)\b",                                # netcat: data exfil / reverse shells
            r"\bpost(message|_message|message)\b",
        )
    ),
    "destructive_irreversible": tuple(re.compile(p, re.IGNORECASE) for p, _ in _DESTRUCTIVE_SPECS),
    # Kernel modules, block devices, storage pools and mounts: changes to the
    # machine itself, almost never part of a coding task, and dangerous even
    # when the agent already runs as root (no sudo for the privilege gate to
    # see). Reported in the wild: an agent created a ZFS pool on /dev/nbd.
    "system_admin": tuple(
        re.compile(p, re.IGNORECASE)
        for p in (
            r"\b(modprobe|insmod|rmmod|kldload|kextload)\b",
            r"\b(qemu-nbd|nbd-client|kpartx|cryptsetup|mdadm)\b",
            r"\blosetup\b(?![^\n]*\s(-l|--list|-a|--all)\b)(?=[^\n]*\S+\s+\S)",   # attaching; `losetup -l` only lists
            r"\b(swapon|swapoff)\b(?![^\n]*\s(--show|-s|--summary)\b)",           # `swapon --show` only lists
            r"\bzpool\s+(create|destroy|add|attach|detach|replace|labelclear|import|export|split)\b",
            r"\bzfs\s+(destroy|rollback|create|set|receive|recv|mount|unmount)\b",
            r"\b(u?mount)\s+[^\n]*(/dev/|\s-o\b|\s--bind\b|\s-t\s)",
            r"\b(sysctl\s+-w|systemctl\s+(stop|disable|mask|enable|restart)|service\s+\S+\s+(stop|restart))\b",
            r"\bchroot\b|\bnsenter\b|\bunshare\b",
        )
    ),
    # Changing ANOTHER agent's own config or permission file (its hooks,
    # allowlists, auto-approve settings, plugins, extensions) can switch off
    # that agent's guards or semgate's plugin in it. Reading them is fine.
    # semgate's own state (~/.semgate) and the agy hook file are hard-denied
    # above. File tools and inline code: agent_config_write().
    "agent_config": tuple(
        re.compile(p, re.IGNORECASE)
        for p in (
            _AGENT_CONFIG_WRITE + r"[^\n]*" + _AGENT_CONFIG_PATHS,
            # The host's own session record (Claude Code transcripts, agy
            # transcripts, OpenCode's message store). semgate reads the
            # user's turns from it (user_asked, chat approval), so a write
            # there could fake a user turn. Reading it stays ungated.
            r"(>>?|\btee\b|\bsed\s+-i\S*|\b(rm|mv|cp|del|erase|remove-item|move-item|copy-item|set-content|add-content|out-file|new-item|clear-content|truncate)\b)[^\n]*"
            + _HOST_TRANSCRIPTS,
            r"open\([^\n]*" + _HOST_TRANSCRIPTS + r"[^\n]*['\"][wa]",
            r"\A(write|edit|create|write_to_file|replace_file_content|multi_replace_file_content)\n[\s\S]*" + _HOST_TRANSCRIPTS,
            # A host CLI that registers an MCP server, plugin, extension or
            # skill in the agent's config (`claude mcp add`, `claude plugin
            # install`, `opencode mcp add`, `gemini extensions install`,
            # `codex mcp add` ...): the server or plugin then runs with every
            # session, and its start command is not a tool call semgate sees.
            r"\b(claude|opencode|codex|gemini|droid|copilot|amp|qwen|cursor-agent|agy)(\.exe)?\s+"
            r"(mcp|plugins?(\s+marketplace)?|extensions?|skills?)\s+(add|add-json|add-from-claude-desktop|install|enable|import|link)\b",
            # Installers that write skills or MCP servers into agent folders
            # or configs: `npx skills add owner/repo`, `npx @smithery/cli install`.
            r"\b(npx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+(-y\s+|--yes\s+)?(skills|@smithery/cli|install-mcp|add-mcp)(@\S+)?\s+(add|install)\b",
        )
    ),
    # Writes into operating-system directories. A download, redirect, copy or
    # script-assembled destination under /usr, /etc, /bin, ... (or C:\Windows)
    # changes the machine, not the project. Reads of those paths are not gated.
    "system_write": tuple(
        re.compile(p, re.IGNORECASE)
        for p in (
            r"\b(wget|curl)\b[^\n]*\s(-O|-o|--output(-document)?)[=\s]*[\"']?/(usr|etc|bin|sbin|lib|lib64|boot|opt|root|dev|var)(/|\b)",  # download into a system dir
            r"(>>?|\btee\b(\s+-a)?)\s*[\"']?/(?!" + _DEV_SINK + r")(usr|etc|bin|sbin|lib|lib64|boot|opt|root|dev)(/|\b)",  # redirect/tee into a system dir (not /dev/null & co.)
            r"\b(cp|mv|install|ln)\b[^\n]*\s[\"']?/(usr|etc|bin|sbin|lib|lib64|boot|opt|root)(/|\b)",                  # copy/move/link involving a system dir
            # A shell variable set to a system-dir path and later used as a write
            # target (`f=/usr/x; ... > "$f"`). The backreference ties the write
            # to that variable, so `CC=/usr/bin/gcc make > build.log` is not gated.
            r"(^|[\s;&|])([A-Za-z_]\w*)=\s*[\"']?/(?!" + _DEV_SINK + r")(usr|etc|bin|sbin|lib|lib64|boot|opt|root|dev)/[^\s\"']*[\"']?[\s\S]*?(>>?|\btee\b(\s+-a)?|\bcp\b[^\n]*|\bmv\b[^\n]*|\binstall\b[^\n]*)\s*[\"']?\$\{?\2\b",
            r"open\(\s*[\"']/(usr|etc|bin|sbin|lib|lib64|boot|opt|root|dev)/[^\"']*[\"']\s*,\s*[\"'][wa]",              # python open(..., 'w'/'a') on a system path
            r"\b(set-content|add-content|out-file|copy-item|move-item|new-item)\b[^\n]*\b[a-z]:\\(windows|program files)",  # PowerShell write into Windows system dirs
            r">>?\s*[\"']?[a-z]:\\(windows|program files)",                                                           # cmd/PS redirect into Windows system dirs
        )
    ),
    # A language runtime used from the shell to spawn commands or import the OS
    # module: `python -c "import os; os.system(...)"` runs whatever string it is
    # given, so the arguments alone never show what executes.
    "embedded_execution": tuple(
        re.compile(p, re.IGNORECASE)
        for p in (
            r"\bos\.(system|popen|exec[lv]p?e?|spawn[lv]p?e?)\s*\(",
            r"\bsubprocess\.(call|run|Popen|check_output|check_call|getoutput|getstatusoutput)\s*\(",
            r"__import__\s*\(\s*[\"']os[\"']\s*\)",
            r"\bchild_process\b|\bexecSync\s*\(",                   # node
            r"Runtime\.getRuntime\(\)\.exec",                       # java
        )
    ),
    "privilege_escalation": tuple(
        re.compile(p, re.IGNORECASE)
        for p in (
            r"\bsudo\b",
            r"\bdoas\b",
            r"\bchmod\s+[0-7]*[67][67]\b",
            r"\bchown\b",
            r"\bsetuid\b",
        )
    ),
    "obfuscated_execution": tuple(
        re.compile(p, re.IGNORECASE)
        for p in (
            r"\b(iex|invoke-expression)\b",            # run a string as code
            r"\bdownloadstring\b",                     # (Net.WebClient).DownloadString
            r"\bfrombase64string\b",                   # decode base64 in .NET
            r"\bcertutil\b[^\n]*-encode\b",
            r"\bbase64\s+(-d|--decode)\b",             # decode base64 on the shell
            r"\beval\b",                               # shell eval: run a string as code
        )
    ),
}


@dataclass(frozen=True)
class RuleResult:
    outcome: str                    # "deny" | "allow" | "none"
    rule: str = ""
    detail: str = ""


@dataclass(frozen=True)
class GateHit:
    gate_class: str
    matched: str
    # untrusted_instruction from a project instruction file: the
    # injection.InjectionHit (its unpinned lines and file, pins.py).
    info: Any = field(default=None, compare=False, repr=False)


def _action_text(envelope: Envelope) -> str:
    """Searchable text: tool name plus a stable rendering of arguments."""
    parts = [envelope.action.tool]
    for key in sorted(envelope.action.arguments):
        parts.append(str(key))
        parts.append(str(envelope.action.arguments[key]))
    return "\n".join(parts)


def _command(envelope: Envelope) -> str:
    c = envelope.action.arguments.get("command")
    return c if isinstance(c, str) else ""


def _hard_text(envelope: Envelope) -> str:
    """Hard denies see everything: the full action text plus any code the
    command runs from inside strings, heredocs or substitutions. Extraction
    can only ADD matches here."""
    scripts = shellparse.extract_scripts(_command(envelope))
    return _action_text(envelope) + ("\n" + "\n".join(scripts) if scripts else "")


def _gate_text(envelope: Envelope) -> str:
    """Human gates see the command with data removed (quoted text given to
    echo/grep/git commit -m ..., comments, data heredocs) plus the extracted
    code. A command that loses a gate this way still goes to the model."""
    command = _command(envelope)
    if not command:
        return _action_text(envelope)
    parts = [envelope.action.tool]
    for key in sorted(envelope.action.arguments):
        parts.append(str(key))
        value = envelope.action.arguments[key]
        parts.append(shellparse.gate_view(command) if key == "command" else str(value))
    scripts = shellparse.extract_scripts(command)
    return "\n".join(parts) + ("\n" + "\n".join(scripts) if scripts else "")


def extract_paths(envelope: Envelope) -> List[str]:
    paths: List[str] = []
    for key in ("path", "file", "file_path", "filepath", "filename", "target", "directory", "dir"):
        value = envelope.action.arguments.get(key)
        if isinstance(value, str) and value:
            paths.append(os.path.expanduser(value))
    command = envelope.action.arguments.get("command")
    if isinstance(command, str):
        for raw in re.split(r"\s+", command):
            token = raw.strip("\"'")   # strip quotes first, so a quoted path is still seen
            if not token:
                continue
            # POSIX absolute/relative, Windows drive-absolute (C:\ or C:/),
            # Windows relative (.\ ..\ ~\), and UNC (\\server\share). Windows
            # paths were previously invisible here, so allowed_path_prefixes was
            # not enforced for them on the gateway's target OS.
            if (token.startswith(("/", "~/", "./", "../", ".\\", "..\\", "~\\"))
                    or token.startswith("\\\\")
                    or re.match(r"[A-Za-z]:[\\/]", token)):
                paths.append(os.path.expanduser(token))
    return paths


def _norm(path: str) -> str:
    return os.path.normpath(os.path.expanduser(path))


def _canonical(path: str) -> str:
    """Canonicalize before scope matching: resolve symlinks/junctions and OS
    aliases (Windows 8.3 short names, \\\\?\\, ..) so an alias cannot smuggle a
    path past allowed_path_prefixes. realpath is trusted only when it resolves to
    something that exists on this host; otherwise (a not-yet-created target, or a
    foreign-OS path such as C:\\ evaluated on Linux) fall back to a plain
    normalize, which keeps the deterministic string behavior and cross-OS tests
    stable. Both the target and each prefix are canonicalized this way."""
    expanded = os.path.expanduser(path)
    try:
        real = os.path.realpath(expanded)
        if os.path.exists(real):
            return real
    except OSError:
        pass
    return os.path.normpath(expanded)


def path_within(path: str, prefixes: Tuple[str, ...]) -> bool:
    target = _canonical(path)
    for prefix in prefixes:
        base = _canonical(prefix)
        if target == base or target.startswith(base.rstrip(os.sep) + os.sep):
            return True
    return False


def check_grant_scope(envelope: Envelope) -> List[str]:
    """Return a list of scope violations; empty list means in scope."""
    grant = envelope.grant
    violations: List[str] = []
    tool = envelope.action.tool

    if grant.allowed_tools and tool not in grant.allowed_tools and "*" not in grant.allowed_tools:
        violations.append(f"tool '{tool}' is not in the grant's allowed_tools")

    text = _action_text(envelope)
    for pattern in grant.forbidden_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            violations.append(f"action matches forbidden pattern '{pattern}'")

    if grant.allowed_path_prefixes:
        own = own_program_words(_command(envelope))
        for path in extract_paths(envelope):
            # semgate's own skill (installed by `semgate init`) tells the agent
            # how to act on semgate's answers: the read tool may read it even
            # when the grant limits paths to the project.
            if tool in SKILL_READ_TOOLS and is_semgate_skill(path):
                continue
            # This install's own semgate command as the program of a simple
            # command (the skill's `<install>/semgate.exe trust add ...`):
            # the program path is not a path the agent touches. One skip per
            # program word found; the same text anywhere else still counts.
            if own.get(path, 0) > 0:
                own[path] -= 1
                continue
            if not path_within(path, grant.allowed_path_prefixes):
                violations.append(f"path '{path}' is outside the grant's allowed_path_prefixes")

    return violations


def own_program_words(command: str) -> Dict[str, int]:
    """{word: count} of the program words in `command` that are exactly this
    install's own semgate command (skill.own_programs): the first word of a
    simple command (shellparse.split_commands), unquoted and without escapes,
    equal to a console script of this install, or equal to this interpreter
    when the next two words are `-m semgate`. Compared as text
    (skill.program_key), never resolved: another venv's semgate, a copy, a
    link at another path, a lookalike with extra characters, or the path as
    an argument is not in the result. The rest of the command is judged as
    before (hard denies, the trust gate, the other paths)."""
    if not command or "semgate" not in command.lower():
        return {}
    from . import skill
    scripts, pythons = skill.own_programs()
    if not scripts and not pythons:
        return {}
    out: Dict[str, int] = {}
    for simple in shellparse.split_commands(command):
        toks = simple.tokens
        if not toks:
            continue
        first = toks[0]
        if first.redirect or first.quoted or first.raw != first.value or first.substitutions:
            continue
        key = skill.program_key(first.raw)
        if key in scripts:
            pass
        elif (key in pythons and len(toks) >= 3 and toks[1].raw == "-m" and toks[2].raw == "semgate"):
            pass
        else:
            continue
        out[first.raw] = out.get(first.raw, 0) + 1
    return out


def _pins_name_re() -> str:
    from .pins import NAME_RE
    return NAME_RE


# Tools that write or edit a file named in their arguments (canonical and
# host-native names). A path under a `.semgate` folder is semgate's own state
# (config, grant, ledger, feedback, trust store): the agent never writes there.
_FILE_WRITE_TOOLS = frozenset({"write", "edit", "create", "create_file", "write_file", "write_to_file",
                               "replace_file_content", "multi_replace_file_content", "multiedit", "apply_patch", "patch",
                               "notebookedit", "str_replace_based_edit_tool", "replace_string_in_file",
                               "multi_replace_string_in_file", "insert_edit_into_file"})
_SEMGATE_DIR_RE = re.compile(r"(^|[/\\])\.semgate([/\\]|$)")
_WRITE_PATH_KEYS = ("path", "file_path", "filePath", "filepath", "TargetFile", "targetFile", "target_file", "FilePath",
                    "AbsolutePath", "notebook_path", "filename")


def semgate_state_write(envelope: Envelope) -> str:
    """The path when a file tool writes under a `.semgate` folder, else ""."""
    if envelope.action.tool.strip().lower() not in _FILE_WRITE_TOOLS:
        return ""
    for key in _WRITE_PATH_KEYS:
        value = envelope.action.arguments.get(key)
        if isinstance(value, str) and _SEMGATE_DIR_RE.search(value.strip().strip('"')):
            return value[:200]
    return ""


def semgate_state_code_write(command: str) -> str:
    """The code when inline code the command runs (python -c, node -e, a
    heredoc given to an interpreter) names a `.semgate` folder and writes
    files, else "". `Path.home() / ".semgate" / "trust.jsonl"` and
    `os.path.join(home, ".semgate", ...)` have no path separator next to the
    name, so the text patterns do not see them. A name built from pieces
    ('.sem' + 'gate') is not seen: deliberate evasion (trustauth.py)."""
    if not command:
        return ""
    for code in shellparse.extract_scripts(command):
        if _CODE_SEMGATE_RE.search(code) and _CODE_WRITE_RE.search(code):
            return code[:200]
    return ""


def check_hard_deny(envelope: Envelope) -> RuleResult:
    text = _hard_text(envelope)
    for pattern in HARD_DENY_PATTERNS:
        match = pattern.search(text)
        if match:
            return RuleResult(outcome="deny", rule="hard_deny", detail=f"matches deny pattern: {match.group(0)!r}")
    # Catastrophic deletes and permission changes in every spelling (rm -fr /,
    # rm -r -f /, rm -rf / --no-preserve-root, find / -delete, chmod -R 777 /,
    # through sudo, bash -c, python -c ...). Parsed, not matched as text
    # (catastrophic.py): the regexes above only see `rm -rf /` at the end of a line.
    catastrophic_what = catastrophic.catastrophic_hit(_command(envelope))
    if catastrophic_what:
        return RuleResult(outcome="deny", rule="hard_deny", detail=catastrophic_what)
    written = semgate_state_write(envelope) or semgate_state_code_write(_command(envelope))
    if written:
        return RuleResult(outcome="deny", rule="hard_deny",
                          detail=f"writes semgate's own state (a .semgate folder): {written!r}")
    command = _command(envelope)
    # semgate's admin commands (init, uninstall, harness init, ...): only the
    # user runs them, in their own terminal (adminguard.py). Parsed, not
    # matched as text: quotes, escapes, paths, `python -m`, wrappers, runners
    # and code in strings (bash -c, $(...), python -c) do not hide them.
    admin = adminguard.admin_hit(command) if command else ""
    if admin:
        return RuleResult(outcome="deny", rule="semgate_admin", detail=f"{admin}: {adminguard.REASON}")
    if command and TRUST_REQUEST_RE.search(command):
        # `semgate trust add "<cmd>"`: a hard-rule command can never be
        # trusted. Each inner command is checked on its own, with the code it
        # runs, because the quotes around it hide it from extract_scripts.
        from .trust import grant_hit, hard_rule_hit, inner_commands
        for inner in inner_commands(command):
            hit = hard_rule_hit(inner)
            if hit:
                return RuleResult(outcome="deny", rule="trust_hard_rule",
                                  detail=f"semgate trust add of a hard-rule command (matches {hit!r}); it can never be trusted")
            hit = grant_hit(inner, envelope.grant.forbidden_patterns)
            if hit:
                return RuleResult(outcome="deny", rule="trust_grant_scope",
                                  detail=f"semgate trust add of a command the grant forbids (pattern {hit!r}); it can never be trusted")
    violations = check_grant_scope(envelope)
    if violations:
        return RuleResult(outcome="deny", rule="grant_scope", detail="; ".join(violations))
    return RuleResult(outcome="none")


_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://([^/\s:'\"]+)", re.IGNORECASE)
# user@host (ssh/scp/rsync). Requires a user token right before @, so a curl
# data arg like `-d @body.json` (space before @) is NOT read as a host.
_HOSTARG_RE = re.compile(r"[a-z0-9_.-]+@([a-z0-9.-]+\.[a-z]{2,}|localhost|\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)


def extract_hosts(command: str) -> List[str]:
    """Hosts a network command talks to: URL authorities plus user@host targets."""
    hosts = [m.group(1).lower() for m in _URL_RE.finditer(command)]
    hosts += [m.group(1).lower() for m in _HOSTARG_RE.finditer(command)]
    return [h.split(":")[0] for h in hosts]


def _host_allowed(host: str, allowed: Tuple[str, ...]) -> bool:
    for a in allowed:
        a = a.lower().lstrip("*.")
        if a == "*" or host == a or host.endswith("." + a):
            return True
    return False


# Using an SSH key to authenticate (ssh/scp -i <key>, IdentityFile) is not the
# same as reading or sending the key. The first is normal dev (reach your own
# server); the second is exfil. We tell them apart by whether each key token sits
# right after an identity flag.
_KEY_TOKEN_RE = re.compile(r"[^\s'\"]*(?:id_rsa|id_ed25519|id_ecdsa|\.pem|\.key|\.ssh[/\\][^\s'\"]+)[^\s'\"]*", re.I)
_AUTH_PRE_RE = re.compile(r"(-i|--identity|--identity-file|identityfile\s*=?)$", re.I)
_SECRET_READ_VERB_RE = re.compile(r"\b(cat|type|more|less|head|tail|get-content|gc|base64|openssl|xxd|certutil)\b", re.I)
_SECRET_SEND_RE = re.compile(r"\b(curl|wget|iwr|invoke-webrequest|irm)\b[^\n]*[@=]", re.I)
_NON_SSH_SECRET_RE = re.compile(r"\.env\b|\.aws[/\\]|\.gnupg[/\\]|\.netrc\b|credentials?\.(json|xml|ini|ya?ml)\b|/etc/shadow|\bkeychain\b", re.I)


def ssh_key_auth_use_only(command: str) -> bool:
    """True when every SSH-key reference is an identity flag (-i / IdentityFile),
    the command reads or sends no secret, and it names no non-SSH secret. Then the
    key is used, not exfiltrated, so the credentials gate does not apply."""
    tokens = [(m.start(), m.group(0)) for m in _KEY_TOKEN_RE.finditer(command)]
    if not tokens or _NON_SSH_SECRET_RE.search(command):
        return False
    # A key token not sitting right after an identity flag is a source/read/send target.
    for pos, _ in tokens:
        pre = command[:pos].rstrip().rstrip("'\"").rstrip()
        if not _AUTH_PRE_RE.search(pre):
            return False
    if _SECRET_READ_VERB_RE.search(command) or _SECRET_SEND_RE.search(command):
        return False
    return True


def network_in_scope(envelope: Envelope) -> bool:
    """True when the action is a network call whose every host is declared in the
    grant's allowed_domains and it references no secret. This is the operator's
    per-task context: the endpoints this task is allowed to talk to."""
    grant = envelope.grant
    if not grant.allowed_domains:
        return False
    command = str(envelope.action.arguments.get("command", "")) + " " + str(envelope.action.arguments.get("url", ""))
    hosts = extract_hosts(command)
    if not hosts:
        return False
    if any(not _host_allowed(h, grant.allowed_domains) for h in hosts):
        return False
    # Reading or sending a secret is never in scope, even to an allowed host.
    # Using an SSH key to authenticate (ssh -i key deploy@host) is fine.
    if ssh_key_auth_use_only(command):
        return True
    for pattern in GATE_PATTERNS["credentials_secrets"]:
        if pattern.search(_action_text(envelope)):
            return False
    return True


# The compiled destructive patterns whose flag in _DESTRUCTIVE_SPECS is True.
# An identity set built from the same tuple the gate uses, never from strings,
# so editing a pattern (as F1 did for `> /dev/null`) cannot silently drop it
# from the relaxable set.
RELAXABLE_DESTRUCTIVE = frozenset(
    id(p) for p, (_, relaxable) in zip(GATE_PATTERNS["destructive_irreversible"], _DESTRUCTIVE_SPECS) if relaxable
)


def recoverable_destructive_only(envelope: Envelope) -> bool:
    """True when the ONLY destructive patterns the command matches are file
    deletes/overwrites/discards that git can undo when the targets are clean
    (rm, `> /abs`, git checkout -- / restore / switch --discard-changes,
    recursive Remove-Item / del /s). Anything else destructive (shred,
    truncate, force push, reset --hard, clean -f, SQL drop/delete, kill) is
    never relaxable. The relaxable set is the flag in _DESTRUCTIVE_SPECS."""
    text = _gate_text(envelope)
    matched = [p for p in GATE_PATTERNS["destructive_irreversible"] if p.search(text)]
    return bool(matched) and all(id(p) in RELAXABLE_DESTRUCTIVE for p in matched)


def script_network_hit(scripts: List[str]) -> str:
    """The first network-library use found in code the command runs, or ""."""
    for code in scripts:
        for pattern in SCRIPT_NETWORK_PATTERNS:
            match = pattern.search(code)
            if match:
                return match.group(0)[:120]
    return ""


# The agent writing or editing a project instruction file (AGENTS.md,
# CLAUDE.md, ... pins.is_instruction_file): the user's pinned command lines
# live there, so every such write is a human gate (instruction_file_edit).
_NAME_END = r"(?=$|[\s'\";&|<>)])"
_PATH_TO_NAME = r"['\"]?[^\s'\";&|<>]*?(?<![\w.-])" + _pins_name_re() + _NAME_END


def _write_regex(path: str) -> "re.Pattern":
    """A shell command that writes, moves or deletes a file whose path
    matches `path` (a regex for one path word)."""
    return re.compile(
        # a redirect into the file: > >> >|
        r"(?:>>?|>\|)\s*" + path
        # a program that writes, moves or deletes the files it names (any argument)
        + r"|(?:\btee\b|\bsed\b[^\n|;&]*?\s-i\S*|\bperl\b[^\n|;&]*?\s-\w*i\S*"
          r"|\b(?:mv|rm|del|erase|move|ren|rename|truncate|touch|dd|set-content|add-content|out-file|new-item"
          r"|remove-item|move-item|clear-content|rename-item)\b)[^\n|;&<>]*?(?:\s|=|:)" + path
        # a copy or link: only when the file is the last argument (the destination)
        + r"|\b(?:cp|copy|copy-item|ln|install)\b[^\n|;&<>]*\s" + path + r"['\"]?\s*(?=$|[;&|)\n])",
        re.IGNORECASE | re.MULTILINE)


_INSTRUCTION_EDIT_RE = _write_regex(_PATH_TO_NAME)

# Agent skill folders. A skill file is read by the host in later sessions and
# steers the agent like an instruction file, so writing one is the same human
# gate (instruction_file_edit). Any folder named `skills` (OpenCode also
# `skill`) directly under a coding agent's folder, at user level or inside a
# project: ~/.claude/skills, ~/.gemini/config/skills, ~/.agents/skills,
# ~/.codex/skills, ~/.copilot/skills, ~/.factory/skills, ~/.config/opencode/skills,
# ~/.pi/agent/skills, <project>/.claude/skills, <project>/.opencode/skill, ...
_SKILL_DIR = (r"\.(?:claude|agents|codex|copilot|factory|opencode|cursor|windsurf|gemini(?:[/\\]+config)?"
              r"|config[/\\]+opencode|pi(?:[/\\]+agent)?)[/\\]+skills?(?=[/\\'\"\s;&|<>)]|$)")
SKILL_PATH_RE = re.compile(r"(?<![\w.-])" + _SKILL_DIR, re.IGNORECASE)
_PATH_TO_SKILL = r"['\"]?[^\s'\";&|<>]*?(?<![\w.-])" + _SKILL_DIR + r"[^\s'\";&|<>]*"
_SKILL_EDIT_RE = _write_regex(_PATH_TO_SKILL)
# Programs that fetch, unpack, sync or create files in a folder they name
# (git clone, a download, an archive, mkdir): with a skill folder anywhere in
# their arguments, the command can install or change a skill.
_SKILL_FETCH_RE = re.compile(
    r"\b(?:git|curl|wget|iwr|invoke-webrequest|irm|unzip|tar|expand-archive|rsync|scp|robocopy|xcopy|mkdir|md)\b"
    r"[^\n|;&<>]*?(?:\s|=|:)" + _PATH_TO_SKILL, re.IGNORECASE | re.MULTILINE)
_PATCH_FILE_RE = re.compile(r"^\*\*\* (?:Add|Update|Delete) File: (.+?)\s*$", re.MULTILINE)
_OPEN_WRITE_RE = re.compile(r"\bopen\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"](?:[wax]b?\+?|r\+b?|rb\+)['\"]")


def is_skill_path(path: str) -> bool:
    """True for a path inside an agent skill folder (SKILL_PATH_RE)."""
    return isinstance(path, str) and bool(SKILL_PATH_RE.search(path.strip().strip("'\"")))


def instruction_file_edit(envelope: Envelope) -> str:
    """What names the instruction file or agent skill file the action
    writes, or ""."""
    from .pins import is_instruction_file

    def steering(path: str) -> bool:
        return is_instruction_file(path) or is_skill_path(path)
    tool = envelope.action.tool.strip().lower()
    args = envelope.action.arguments
    if tool in _FILE_WRITE_TOOLS:
        for key in _WRITE_PATH_KEYS:
            value = args.get(key)
            if isinstance(value, str) and steering(value):
                return f"{envelope.action.tool} {value}"[:120]
        for value in args.values():
            if isinstance(value, str):
                for m in _PATCH_FILE_RE.finditer(value):
                    if steering(m.group(1)):
                        return f"{envelope.action.tool} {m.group(1)}"[:120]
    command = _command(envelope)
    if command:
        text = _gate_text(envelope)
        for rx in (_INSTRUCTION_EDIT_RE, _SKILL_EDIT_RE, _SKILL_FETCH_RE):
            m = rx.search(text)
            if m:
                return m.group(0).strip()[:120]
        for code in shellparse.extract_scripts(command):
            for m in _OPEN_WRITE_RE.finditer(code):
                if steering(m.group(1)):
                    return m.group(0)[:120]
    return ""


# A pipe into a shell or interpreter: the text before it may be code.
_PIPE_TO_SHELL = re.compile(r"\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\|\s*(?:pwsh|powershell|cmd|iex|invoke-expression"
                            r"|python\d*|py|node|xargs)\b", re.IGNORECASE)


def agent_config_write(envelope: Envelope) -> str:
    """What writes an agent config file (AGENT_CONFIG_PATH_RE) with a file
    tool (write, edit, apply_patch, ...: the path arguments and the files a
    patch names) or from inline code (python -c, node -e, heredocs: a file
    write next to such a path), else "". Shell commands are GATE_PATTERNS."""
    tool = envelope.action.tool.strip().lower()
    args = envelope.action.arguments
    if tool in _FILE_WRITE_TOOLS:
        for key in _WRITE_PATH_KEYS:
            value = args.get(key)
            if isinstance(value, str) and AGENT_CONFIG_PATH_RE.search(value.strip().strip("'\"")):
                return f"{envelope.action.tool} {value}"[:120]
        for value in args.values():
            if isinstance(value, str):
                for m in _PATCH_FILE_RE.finditer(value):
                    if AGENT_CONFIG_PATH_RE.search(m.group(1)):
                        return f"{envelope.action.tool} {m.group(1)}"[:120]
    command = _command(envelope)
    if command and AGENT_CONFIG_PATH_RE.search(command):
        for code in shellparse.extract_scripts(command):
            if AGENT_CONFIG_PATH_RE.search(code) and _CODE_WRITE_RE.search(code):
                return code[:120]
    return ""


def detect_gates(envelope: Envelope, path_dirs: Sequence[str] = (), pins: Any = None) -> List[GateHit]:
    """`pins` (pins.PinView): lines of project instruction files the user
    pinned are not untrusted instructions (injection.detect)."""
    text = _gate_text(envelope)
    in_scope_net = network_in_scope(envelope)
    command = str(envelope.action.arguments.get("command", ""))
    # Using an SSH key to authenticate (not reading/sending it) is not a secret gate.
    key_use = ssh_key_auth_use_only(command)
    hits: List[GateHit] = []
    for gate_class, patterns in GATE_PATTERNS.items():
        # A network call to a declared task endpoint is not an exfil gate.
        if gate_class == "external_communication" and in_scope_net:
            continue
        if gate_class == "credentials_secrets" and key_use:
            continue
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                hits.append(GateHit(gate_class=gate_class, matched=match.group(0)[:120]))
                break
    # `semgate trust add` hidden from the gate view (e.g. inside quoted text
    # given to echo, or with quotes inside its words) is still a trust
    # request: the full action text and the shell's own words decide. A
    # strictly parsed `semgate trust list` / `remove` is not one.
    # semgate_admin: shell commands only (a file tool's content is text, not
    # a command), and not a strictly parsed `semgate init --help`. An admin
    # command hidden in text piped into a shell (`echo semgate init | bash`)
    # is found in the command as written: the gate view drops echo's words.
    # The gate view has one simple command per line; here the lines are
    # joined, so `S=semgate; $S init` is seen as one text.
    hits = [h for h in hits if h.gate_class != "semgate_admin"]
    if command and not adminguard.harmless(command):
        flat = " ; ".join(line for line in text.splitlines() if line.strip())
        found = adminguard.text_hit(flat)
        if not found and _PIPE_TO_SHELL.search(command):
            found = adminguard.text_hit(" ; ".join(command.splitlines()))
        if found:
            at = 1 if hits and hits[0].gate_class == "trust_request" else 0
            hits.insert(at, GateHit(gate_class="semgate_admin", matched=found))
    written = agent_config_write(envelope)
    if written and not any(h.gate_class == "agent_config" for h in hits):
        hits.append(GateHit(gate_class="agent_config", matched=written))
    from .trust import harmless, request_hit
    if command and harmless(command):
        hits = [h for h in hits if h.gate_class != "trust_request"]
    elif not any(h.gate_class == "trust_request" for h in hits):
        match = TRUST_REQUEST_RE.search(_action_text(envelope))
        found = match.group(0)[:120] if match else request_hit(command)
        if found:
            hits.insert(0, GateHit(gate_class="trust_request", matched=found))
    # Network use inside code the command runs (python -c, node -e, heredocs
    # fed to an interpreter, bash -c "python -c ..."). Only the extracted code
    # is searched, never the whole command line.
    if not any(h.gate_class == "embedded_execution" for h in hits):
        net = script_network_hit(shellparse.extract_scripts(command)) if command else ""
        if net:
            hits.append(GateHit(gate_class="embedded_execution", matched=f"network use in inline code: {net}"[:120]))
    # A link that plants something in a persistence location (a shell startup
    # file, ~/.ssh, an autostart, service or cron folder, a folder on PATH, git
    # hooks, editor or coding-agent settings, a new entry directly in /), or
    # that points to one so a later write through the link changes it. The
    # paths are computed from the parsed command (linkplace.py: ln, cp -s/-l,
    # link, New-Item, mklink; after cd; inside bash -c; links made by inline
    # Python or Node code), not searched as text. `path_dirs`: the folders of
    # the live PATH (linkplace.live_path_dirs at hook time; evals pass a fixed
    # PATH or none). A link fully inside one repo is checked by name only
    # (linkplace.same_repo).
    if command:
        cwd = envelope.environment.cwd or envelope.environment.project_root
        for link_hit in linkplace.persistence_hits(command, cwd, envelope.environment.project_root, path_dirs):
            hits.append(GateHit(gate_class="persistence_link", matched=link_hit.text()[:200]))
            break
    # Indirect prompt injection: the command carries out an instruction found in
    # content the agent read (file, web page, command output). See injection.py.
    # The source (file path, URL or command) comes first so the 200-char cap
    # never cuts it: the block text tells the user which file asked for it.
    for hit in injection.detect(envelope, pins=pins):
        where = f"in output of {hit.tool}" + (f" ({hit.source})" if hit.source else "")
        hits.append(GateHit(gate_class="untrusted_instruction",
                            matched=f"{where}: {hit.marker!r} next to {hit.overlap!r}"[:200],
                            info=hit if hit.file_lines is not None else None))
        break
    edit = instruction_file_edit(envelope)
    if edit:
        hits.append(GateHit(gate_class="instruction_file_edit", matched=edit))
    return hits


def script_gate_hits(scripts: List["Any"], project_root: str = "", path_dirs: Sequence[str] = ()) -> List[GateHit]:
    """F4: gates over the content of local script files the command runs
    (scriptsource.ScriptFile). The same checks inline code gets: human gates,
    the network-library check, and the hard-deny patterns. A hard-deny pattern
    inside a file is reported as the gate `script_denylisted` (ask), not a
    deny: a file holds names like `def shutdown` the denylist was not written
    for, and a human must be able to approve. Only adds gates."""
    from . import scriptsource
    hits: List[GateHit] = []
    seen = set()

    def add(gate_class: str, where: str, text: str) -> None:
        if gate_class not in seen:
            seen.add(gate_class)
            hits.append(GateHit(gate_class=gate_class, matched=f"in {where}: {text}"[:160]))

    for script in scripts:
        hard_text, gate_text = scriptsource.gate_texts(script)
        for pattern in HARD_DENY_PATTERNS:
            match = pattern.search(hard_text)
            if match:
                add("script_denylisted", script.rel, match.group(0)[:120])
                break
        for gate_class, patterns in GATE_PATTERNS.items():
            for pattern in patterns:
                match = pattern.search(gate_text)
                if match:
                    add(gate_class, script.rel, match.group(0)[:120])
                    break
        net = script_network_hit(scriptsource.code_for_network_check(script))
        if net:
            add("embedded_execution", script.rel, f"network use: {net}")
        # Links the script creates: ln and friends in shell scripts, os.symlink,
        # Path.symlink_to, fs.symlinkSync ... with literal paths in Python and
        # Node scripts. Relative paths resolve against the folder the command
        # runs the script in (ScriptFile.run_cwd); without it only absolute
        # and home paths are known.
        for link_hit in linkplace.script_persistence_hits(script, project_root, path_dirs):
            add("persistence_link", script.rel, link_hit.text())
            break
    return hits


def check_hard_allow(envelope: Envelope, allow_tools: Tuple[str, ...] = DEFAULT_HARD_ALLOW_TOOLS) -> RuleResult:
    """Conservative deterministic allow: a read-only tool, in-scope, no gate.
    The read tool may also read an installed agent skill file outside the
    project (installed_skill_root): the host loads skills anyway, and
    semgate's own skill tells the agent how to act on semgate's answers."""
    if envelope.action.tool not in allow_tools:
        return RuleResult(outcome="none")
    if check_grant_scope(envelope):
        return RuleResult(outcome="none")
    root = envelope.environment.project_root
    skills: List[str] = []
    if root:
        for path in extract_paths(envelope):
            if path_within(path, (root,)):
                continue
            if envelope.action.tool in SKILL_READ_TOOLS and installed_skill_root(path):
                skills.append(path)
                continue
            return RuleResult(outcome="none")
    if skills:
        return RuleResult(outcome="allow", rule="hard_allow",
                          detail=f"read-only tool '{envelope.action.tool}' reads an installed agent skill file: {skills[0]}"[:300])
    return RuleResult(outcome="allow", rule="hard_allow", detail=f"read-only tool '{envelope.action.tool}' inside grant scope")


# User-level skill folders where `semgate init` installs semgate's skill
# (skill.py LOCATIONS) and the hosts load skills from. Relative to the home
# folder.
SKILL_HOME_DIRS: Tuple[str, ...] = (".claude/skills", ".gemini/config/skills", ".agents/skills")
# Only the plain read tool (agy view_file, Claude Read, OpenCode read ...):
# not a shell command, not a search.
SKILL_READ_TOOLS = frozenset({"read"})


def installed_skill_root(path: str) -> str:
    """The skill folder (SKILL_HOME_DIRS under the home folder) that holds
    `path`, or "". Both sides are resolved first (_canonical: links,
    junctions, short names, ..), so a link inside a skill folder that points
    elsewhere (~/.ssh/id_rsa) is not inside it."""
    if not isinstance(path, str) or not path.strip():
        return ""
    target = os.path.normcase(_canonical(path.strip().strip("'\"")))
    home = os.path.expanduser("~")
    for rel in SKILL_HOME_DIRS:
        base = os.path.normcase(_canonical(os.path.join(home, *rel.split("/"))))
        if target.startswith(base.rstrip(os.sep) + os.sep):
            return base
    return ""


def is_semgate_skill(path: str) -> bool:
    """True for semgate's own SKILL.md in an installed skill folder."""
    base = installed_skill_root(path)
    if not base:
        return False
    target = os.path.normcase(_canonical(path.strip().strip("'\"")))
    return os.path.relpath(target, base) == os.path.normcase(os.path.join("semgate", "SKILL.md"))
