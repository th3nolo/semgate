"""File reads of supported curl argv forms. Unknown options remain incomplete.

This is payload inspection, not a shell interpreter or an execution boundary.
Use the prepared sender when authorization must bind to the bytes transmitted.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import List
from urllib.parse import quote

from . import shellparse

_BODY = {"--upload-file", "-T", "--data", "-d", "--data-ascii", "--data-binary", "--data-urlencode", "--data-raw",
         "--json", "--form", "-F", "--form-string", "--header", "-H"}
_VALUE = {"--url", "--request", "-X", "--output", "-o", "--max-time", "-m", "--connect-timeout",
          "--noproxy", "--user-agent", "-A", "--write-out", "-w"}
_FLAGS = {"--silent", "-s", "--show-error", "-S", "-sS", "-Ss", "--fail", "-f", "--fail-with-body",
          "--globoff", "-g", "--no-progress-meter", "--head", "-I", "--compressed", "--http1.1",
          "--http2", "--http3", "--disable", "-q", "--remote-name", "-O"}
_SHORT_VALUE = {v for v in _BODY | _VALUE if v.startswith("-") and not v.startswith("--")}


@dataclass
class CommandFiles:
    references: List[str] = field(default_factory=list)
    problems: List[str] = field(default_factory=list)
    inline_json: List[str] = field(default_factory=list)
    inline_forms: List[str] = field(default_factory=list)
    changes_directory: bool = False

    def problem(self, code: str) -> None:
        if code not in self.problems:
            self.problems.append(code)


def _payload(result: CommandFiles, option: str, value: str) -> None:
    reference = ""
    if option in {"--upload-file", "-T"}:
        reference = value
    elif option in {"--form", "-F"}:
        if "=" not in value:
            result.problem("unsupported_form")
            return
        part = value.split("=", 1)[1]
        if part.startswith(("@", "<")):
            reference = part[1:].split(";", 1)[0]
            if "," in reference or ";" in part:
                result.problem("unsupported_form_attributes")
        elif ";headers=" in part.lower():
            result.problem("unsupported_form_attributes")
    elif option == "--data-urlencode":
        # curl's name@file form differs from name=value and literal content.
        if "@" in value and ("=" not in value or value.index("@") < value.index("=")):
            reference = value.split("@", 1)[1]
        elif "=" in value:
            key, cell = value.split("=", 1)
            # curl encodes this value itself; its literal '+' is not a space.
            result.inline_forms.append(key + "=" + quote(cell, safe=""))
    elif option not in {"--form-string", "--data-raw"} and value.startswith("@"):
        reference = value[1:]
    if reference in {"-", "."}:
        result.problem("stdin_payload")
    elif reference:
        result.references.append(reference)
    elif value in {"", "@", "<"}:
        result.problem("empty_payload_reference")
    elif option in {"--json", "--data", "-d", "--data-ascii", "--data-binary", "--data-raw"}:
        if option == "--json" or value.lstrip().startswith(("{", "[")):
            result.inline_json.append(value)
        elif "=" in value:
            result.inline_forms.append(value)


def file_references(command: str) -> CommandFiles:
    result = CommandFiles()
    for simple in shellparse.split_commands(command):
        tokens = shellparse.effective_argv(simple.tokens)
        if not tokens:
            continue
        # Preserve Windows path backslashes; the shared lexer also handles POSIX.
        values = []
        for token in tokens:
            raw = token.raw
            if len(raw) > 1 and raw[0] == raw[-1] and raw[0] in "\"'":
                raw = raw[1:-1]
            values.append(raw if re.match(r"[A-Za-z]:[\\/]", raw) else token.value)
        program = values[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
        if program in {"cd", "chdir", "pushd", "popd", "set-location", "sl"}:
            result.changes_directory = True
        if program not in {"curl", "curl.exe"}:
            if program in {"wget", "wget.exe", "nc", "ncat", "netcat"}:
                # These transports can read local bodies through grammars we
                # do not inspect. An empty finding set is not completeness.
                result.problem("unsupported_transport")
            # PowerShell's file argument has a token boundary, too.
            for index, value in enumerate(values):
                if value.lower() == "-infile":
                    if index + 1 < len(values):
                        result.references.append(values[index + 1])
                    else:
                        result.problem("missing_payload_argument")
            continue
        if any(t.redirect or t.substitutions for t in simple.tokens) or simple.heredocs:
            result.problem("indirect_payload")
        index = 1
        while index < len(values):
            value = values[index]
            if value == "--":
                break
            if not value.startswith("-"):
                index += 1
                continue
            option, argument = value, None
            if value.startswith("--") and "=" in value:
                option, argument = value.split("=", 1)
            elif len(value) > 2 and value[:2] in _SHORT_VALUE:
                option, argument = value[:2], value[2:]
            if option in _FLAGS and argument is None:
                index += 1
                continue
            if option not in _BODY | _VALUE:
                result.problem("unsupported_curl_option")
                index += 1
                continue
            if argument is None:
                index += 1
                if index >= len(values):
                    result.problem("missing_payload_argument")
                    break
                argument = values[index]
            if option in _BODY:
                _payload(result, option, argument)
            index += 1
    return result
